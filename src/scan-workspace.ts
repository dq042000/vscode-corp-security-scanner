import * as vscode from 'vscode';
import axios from 'axios';
import { loadConfig, getGitRemoteUrl, sendScanRequest, formatAxiosError } from './api-client';
import type { ScanConfig, ScanFinding, FileScanResult } from './types';

async function collectFiles(config: ScanConfig): Promise<vscode.Uri[]> {
    const include = config.includePatterns.length === 1
        ? config.includePatterns[0]
        : `{${config.includePatterns.join(',')}}`;

    const exclude = config.excludePatterns.length === 1
        ? config.excludePatterns[0]
        : `{${config.excludePatterns.join(',')}}`;

    const files = await vscode.workspace.findFiles(include, exclude);
    return files.sort((a, b) => a.fsPath.localeCompare(b.fsPath));
}

async function runConcurrent<T, R>(
    items: T[],
    concurrency: number,
    fn: (item: T) => Promise<R>,
    isCancelled: () => boolean,
): Promise<R[]> {
    const results: R[] = new Array(items.length);
    let nextIdx = 0;

    const worker = async () => {
        while (!isCancelled()) {
            const idx = nextIdx++;
            if (idx >= items.length) { break; }
            results[idx] = await fn(items[idx]);
        }
    };

    await Promise.all(
        Array.from({ length: Math.min(concurrency, items.length) }, () => worker()),
    );
    return results;
}

function severityToDiagnostic(severity?: string): vscode.DiagnosticSeverity {
    switch (severity?.toLowerCase()) {
        case 'critical':
        case 'high':
            return vscode.DiagnosticSeverity.Error;
        case 'medium':
            return vscode.DiagnosticSeverity.Warning;
        case 'low':
        case 'info':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Warning;
    }
}

function findingToDiagnostic(f: ScanFinding): vscode.Diagnostic {
    const startLine = Math.max(0, (f.line ?? 1) - 1);
    const startCol = Math.max(0, (f.column ?? 1) - 1);
    const endLine = Math.max(startLine, (f.endLine ?? f.line ?? 1) - 1);
    const endCol = f.endColumn ? Math.max(0, f.endColumn - 1) : 200;

    const range = new vscode.Range(startLine, startCol, endLine, endCol);
    let message = `${f.title ?? 'Security finding'}: ${f.description ?? ''}`.trim();
    if (f.suggestion) {
        message += `\n💡 建議：${f.suggestion}`;
    }

    const diag = new vscode.Diagnostic(range, message, severityToDiagnostic(f.severity));
    diag.source = 'Corp Security Scanner';
    return diag;
}

function applyDiagnostics(
    diagnostics: vscode.DiagnosticCollection,
    results: FileScanResult[],
): void {
    diagnostics.clear();
    for (const result of results) {
        if (result.status !== 'success' || !result.response?.findings?.length) { continue; }
        const uri = vscode.Uri.file(result.filePath);
        diagnostics.set(uri, result.response.findings.map(findingToDiagnostic));
    }
}

export function registerScanWorkspaceCommand(
    context: vscode.ExtensionContext,
    output: vscode.OutputChannel,
    diagnostics: vscode.DiagnosticCollection,
): void {
    const disposable = vscode.commands.registerCommand('corp-security-scanner.scanWorkspace', async () => {
        const config = loadConfig();

        output.appendLine('[workspace-scan] Collecting files...');
        const files = await collectFiles(config);

        if (files.length === 0) {
            vscode.window.showWarningMessage('未找到可掃描的程式碼檔案。');
            return;
        }

        const proceed = await vscode.window.showInformationMessage(
            `找到 ${files.length} 個檔案，確定開始掃描？`,
            { modal: true },
            '開始掃描',
        );
        if (proceed !== '開始掃描') { return; }

        const remoteUrl = await getGitRemoteUrl();
        const allResults: FileScanResult[] = [];
        let scanned = 0;
        let failed = 0;
        let totalFindings = 0;

        output.appendLine(`[workspace-scan] Starting: ${files.length} files, concurrency=${config.concurrency}`);

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: '正在掃描專案...',
            cancellable: true,
        }, async (progress, token) => {
            const results = await runConcurrent(
                files,
                config.concurrency,
                async (uri: vscode.Uri): Promise<FileScanResult> => {
                    if (token.isCancellationRequested) {
                        return { filePath: uri.fsPath, status: 'cancelled' };
                    }

                    const relativePath = vscode.workspace.asRelativePath(uri);

                    try {
                        const doc = await vscode.workspace.openTextDocument(uri);
                        const code = doc.getText();
                        if (!code.trim()) {
                            output.appendLine(`[workspace-scan] Skip (empty): ${relativePath}`);
                            return { filePath: uri.fsPath, status: 'skipped' };
                        }

                        const response = await sendScanRequest({
                            code,
                            fileName: uri.fsPath,
                            remoteUrl,
                            user: vscode.env.machineId,
                        }, config, output);

                        scanned++;
                        const findingCount = response.findings?.length ?? 0;
                        totalFindings += findingCount;

                        progress.report({
                            message: `${scanned}/${files.length} 已掃描（${totalFindings} 個發現）`,
                            increment: (1 / files.length) * 100,
                        });
                        output.appendLine(`[workspace-scan] ✅ ${relativePath} (${findingCount} findings)`);
                        return { filePath: uri.fsPath, status: 'success', response };
                    } catch (err: unknown) {
                        failed++;
                        scanned++;
                        const detail = formatAxiosError(err);
                        output.appendLine(`[workspace-scan] ❌ ${relativePath}: ${detail}`);

                        if (axios.isAxiosError(err)) {
                            output.appendLine(`[workspace-scan]    response: ${JSON.stringify(err.response?.data ?? null)}`);
                        }

                        progress.report({
                            message: `${scanned}/${files.length} 已掃描（${failed} 失敗）`,
                            increment: (1 / files.length) * 100,
                        });
                        return { filePath: uri.fsPath, status: 'failed', error: detail };
                    }
                },
                () => token.isCancellationRequested,
            );

            allResults.push(...results);
        });

        // Summary
        const successResults = allResults.filter(r => r.status === 'success');
        const failedResults = allResults.filter(r => r.status === 'failed');
        const cancelledResults = allResults.filter(r => r.status === 'cancelled');
        const skippedResults = allResults.filter(r => r.status === 'skipped');

        output.appendLine('');
        output.appendLine('══════════════════════════════════');
        output.appendLine(' 專案掃描摘要');
        output.appendLine('══════════════════════════════════');
        output.appendLine(`  總檔案數：${files.length}`);
        output.appendLine(`  成功掃描：${successResults.length}`);
        output.appendLine(`  掃描失敗：${failedResults.length}`);
        output.appendLine(`  已跳過：  ${skippedResults.length}`);
        if (cancelledResults.length > 0) {
            output.appendLine(`  已取消：  ${cancelledResults.length}`);
        }
        output.appendLine(`  弱點總數：${totalFindings}`);
        output.appendLine('══════════════════════════════════');

        // Apply diagnostics for inline editor warnings
        applyDiagnostics(diagnostics, allResults);

        // Notification
        if (cancelledResults.length > 0) {
            vscode.window.showWarningMessage(
                `掃描已取消。已完成 ${successResults.length + failedResults.length}/${files.length} 檔案，發現 ${totalFindings} 個弱點。`,
            );
        } else if (failedResults.length > 0) {
            vscode.window.showWarningMessage(
                `掃描完成，${failedResults.length} 個檔案失敗。共掃描 ${successResults.length} 檔，發現 ${totalFindings} 個弱點。`,
            );
        } else {
            vscode.window.showInformationMessage(
                `✅ 專案掃描完成！共掃描 ${successResults.length} 個檔案，發現 ${totalFindings} 個弱點。`,
            );
        }

        output.show(true);
    });

    context.subscriptions.push(disposable);
}
