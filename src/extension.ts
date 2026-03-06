import * as vscode from 'vscode';
import { registerScanFileCommand } from './scan-file';
import { registerScanWorkspaceCommand } from './scan-workspace';

export function activate(context: vscode.ExtensionContext) {
    const output = vscode.window.createOutputChannel('Corp Security Scanner');
    const diagnostics = vscode.languages.createDiagnosticCollection('corp-security-scanner');

    registerScanFileCommand(context, output);
    registerScanWorkspaceCommand(context, output, diagnostics);

    context.subscriptions.push(output, diagnostics);
}