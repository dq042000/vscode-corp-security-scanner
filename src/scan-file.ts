import * as vscode from 'vscode';
import axios from 'axios';
import {
    CONFIG_SECTION, DEFAULT_API_URL, DEFAULT_TIMEOUT_MS,
    loadConfig, getGitRemoteUrl, sendScanRequest, formatAxiosError, shouldSkipFile,
} from './api-client';

const LARGE_CODE_THRESHOLD = 50000;
type IssueIdentifier = string | number;

function normalizeIssueId(value: unknown): IssueIdentifier | undefined {
    if (typeof value === 'number' && Number.isFinite(value)) {
        return Math.trunc(value);
    }
    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) { return undefined; }
        const numeric = Number(trimmed);
        if (Number.isInteger(numeric) && String(numeric) === trimmed) {
            return numeric;
        }
        return trimmed;
    }
    return undefined;
}

function collectIssueIds(result: Record<string, unknown>): IssueIdentifier[] {
    const ids = new Map<string, IssueIdentifier>();

    const add = (raw: unknown) => {
        if (Array.isArray(raw)) {
            for (const item of raw) {
                const normalized = normalizeIssueId(item);
                if (normalized !== undefined) {
                    ids.set(String(normalized), normalized);
                }
            }
            return;
        }
        const normalized = normalizeIssueId(raw);
        if (normalized !== undefined) {
            ids.set(String(normalized), normalized);
        }
    };

    add(result.issueId);
    add(result.issueIds);
    add(result.issue_id);
    add(result.issue_ids);

    const findings = result.findings;
    if (Array.isArray(findings)) {
        for (const finding of findings) {
            if (typeof finding !== 'object' || finding === null) { continue; }
            const record = finding as Record<string, unknown>;
            add(record.issueId);
            add(record.issueIds);
            add(record.issue_id);
            add(record.issue_ids);
        }
    }

    return Array.from(ids.values());
}

export function registerScanFileCommand(
    context: vscode.ExtensionContext,
    output: vscode.OutputChannel,
): void {
    const disposable = vscode.commands.registerCommand('corp-security-scanner.scanFile', async () => {
        try {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showErrorMessage('請先開啟一個程式碼檔案');
                return;
            }

            const document = editor.document;

            const skipReason = shouldSkipFile(document.fileName);
            if (skipReason) {
                vscode.window.showWarningMessage(`此檔案不進行掃描（${skipReason}）。`);
                return;
            }

            const selectedText = editor.selection.isEmpty ? '' : document.getText(editor.selection);
            const fullCode = document.getText();
            if (!fullCode.trim()) {
                vscode.window.showWarningMessage('目前檔案內容為空，無法進行掃描。');
                return;
            }

            let code = fullCode;
            if (fullCode.length > LARGE_CODE_THRESHOLD) {
                const selectionOption = '掃描目前選取範圍';
                const fullOption = '仍掃描整份檔案';
                const cancelOption = '取消';
                const message = `檔案內容約 ${fullCode.length} 字元，後端可能逾時。`;

                const choice = await vscode.window.showWarningMessage(
                    message,
                    { modal: true },
                    ...(selectedText ? [selectionOption] : []),
                    fullOption,
                    cancelOption,
                );

                if (!choice || choice === cancelOption) { return; }

                if (choice === selectionOption) {
                    code = selectedText;
                    output.appendLine(`[scan] Large file, scanning selection (${code.length} chars).`);
                } else {
                    output.appendLine(`[scan] Large file, full scan (${code.length} chars).`);
                }
            }

            const config = loadConfig();
            const remoteUrl = await getGitRemoteUrl();

            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'AI 正在分析漏洞並同步至 GitLab...',
                cancellable: false,
            }, async () => {
                const result = await sendScanRequest({
                    code,
                    fileName: document.fileName,
                    remoteUrl,
                    user: vscode.env.machineId,
                }, config, output);

                const issueIds = collectIssueIds(result as Record<string, unknown>);
                const issueCount = issueIds.length;
                const primaryIssueId = issueIds[0];
                const chunkNote = typeof result.chunkCount === 'number' && result.chunkCount > 1
                    ? `（分 ${result.chunkCount} 塊掃描）`
                    : '';
                const msg = issueCount > 1
                    ? `掃描完成${chunkNote}，已建立至少 ${issueCount} 個 GitLab Issue（實際以 GitLab 為準）。`
                    : primaryIssueId !== undefined
                        ? `掃描完成${chunkNote}，GitLab Issue #${primaryIssueId} 已建立。`
                        : `掃描完成${chunkNote}。`;
                vscode.window.showInformationMessage(`✅ ${msg}`);
            });
        } catch (error: unknown) {
            let detail = formatAxiosError(error);

            if (axios.isAxiosError(error)) {
                if (error.response?.status === 404) {
                    const cfg = loadConfig();
                    detail += `。請檢查 API URL 是否正確（目前：${cfg.apiUrl}）。`;
                }
                if (
                    error.response?.status === 500
                    && typeof error.response?.data?.error === 'string'
                    && error.response.data.error.includes('session.idle')
                ) {
                    detail += '。已嘗試自動重試與切塊，若仍失敗請先選取較小範圍或稍後再試。';
                }
                if (error.code === 'ECONNABORTED') {
                    const cfg = loadConfig();
                    detail += `。可提高設定 ${CONFIG_SECTION}.requestTimeoutMs（目前：${cfg.timeoutMs}ms）。`;
                }
                output.appendLine(`[scan] Axios error: ${detail}`);
                output.appendLine(`[scan] response data: ${JSON.stringify(error.response?.data ?? null)}`);
            } else if (error instanceof Error) {
                output.appendLine(`[scan] Error: ${error.stack ?? error.message}`);
            }

            vscode.window.showErrorMessage(`❌ 掃描失敗：${detail}`);
            output.show(true);
        }
    });

    context.subscriptions.push(disposable);
}
