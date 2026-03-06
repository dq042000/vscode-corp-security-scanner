import axios, { type AxiosRequestConfig, type AxiosResponse } from 'axios';
import * as https from 'https';
import * as vscode from 'vscode';
import type { ScanConfig, ScanFinding, ScanResponse } from './types';

export const CONFIG_SECTION = 'corpSecurityScanner';
export const DEFAULT_API_URL = process.env.DEFAULT_API_URL;
export const DEFAULT_TIMEOUT_MS = 120000;

const RETRY_TIMEOUT_MULTIPLIER = 3;
const MAX_TIMEOUT_MS = 300000;
const SERVER_IDLE_TIMEOUT_HINT = 'session.idle';
const SERVER_IDLE_RETRY_DELAY_MS = 2000;
const SERVER_IDLE_TRUNCATE_THRESHOLD = 25000;
const SERVER_IDLE_TRUNCATE_TO_CHARS = 20000;
const AUTO_CHUNK_THRESHOLD = 18000;
const CHUNK_TARGET_CHARS = 12000;
const CHUNK_HARD_MAX_CHARS = 16000;
const IDLE_SPLIT_MAX_DEPTH = 4;
const IDLE_SPLIT_MIN_CHARS = 2000;
const IDLE_SPLIT_MIN_LINES = 20;
const IDLE_SPLIT_MIN_HARD_MAX_CHARS = 2200;
const IDLE_SPLIT_MIN_TARGET_CHARS = 1400;
const GATEWAY_RETRY_DELAY_MS = 1500;
const POLL_INTERVAL_MS = 2000;
const MIN_POLL_WAIT_MS = 60000;

const ASYNC_PENDING_STATUSES = new Set(['accepted', 'pending', 'queued', 'running', 'processing', 'in_progress']);
const ASYNC_SUCCESS_STATUSES = new Set(['completed', 'complete', 'done', 'success', 'succeeded']);
const ASYNC_FAILURE_STATUSES = new Set(['failed', 'error', 'cancelled', 'timeout', 'timed_out']);
const TRANSIENT_GATEWAY_STATUSES = new Set([502, 503, 504]);

const DECLARATION_PATTERNS = [
    /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+[A-Za-z_$][\w$]*/,
    /^\s*(?:export\s+)?(?:abstract\s+)?(?:class|interface|enum)\s+[A-Za-z_$][\w$]*/,
    /^\s*(?:public|private|protected|internal|static|readonly|final|abstract|\s)+(?:class|interface|enum)\s+[A-Za-z_][\w]*/,
    /^\s*(?:public|private|protected|static|final|abstract|\s)*(?:async\s+)?function\s+[A-Za-z_][\w]*/,
    /^\s*(?:public|private|protected|static|readonly|\s)+[A-Za-z_$][\w$<>,\[\]\s]*\([^;]*\)\s*\{/,
    /^\s*(?:def|class)\s+[A-Za-z_][\w]*/,
    /^\s*func\s+(?:\([^)]+\)\s*)?[A-Za-z_][\w]*/,
    /^\s*fn\s+[A-Za-z_][\w]*/,
];

type ChunkStrategy = 'declaration' | 'fixed';
type IssueIdentifier = string | number;

interface ScanCodeChunk {
    index: number;
    startLine: number;
    endLine: number;
    code: string;
    strategy: ChunkStrategy;
}

interface LineRange {
    start: number;
    end: number;
    strategy: ChunkStrategy;
}

interface ChunkBuildOptions {
    autoChunkThreshold: number;
    chunkTargetChars: number;
    chunkHardMaxChars: number;
}

const DEFAULT_CHUNK_BUILD_OPTIONS: ChunkBuildOptions = {
    autoChunkThreshold: AUTO_CHUNK_THRESHOLD,
    chunkTargetChars: CHUNK_TARGET_CHARS,
    chunkHardMaxChars: CHUNK_HARD_MAX_CHARS,
};

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

function collectIssueIdsFromUnknown(
    raw: unknown,
    acc: Map<string, IssueIdentifier>,
): void {
    if (Array.isArray(raw)) {
        for (const item of raw) {
            const normalized = normalizeIssueId(item);
            if (normalized !== undefined) {
                acc.set(String(normalized), normalized);
            }
        }
        return;
    }

    const normalized = normalizeIssueId(raw);
    if (normalized !== undefined) {
        acc.set(String(normalized), normalized);
    }
}

function collectIssueIdsFromResponse(response: ScanResponse): IssueIdentifier[] {
    const ids = new Map<string, IssueIdentifier>();
    const record = response as Record<string, unknown>;

    collectIssueIdsFromUnknown(response.issueId, ids);
    collectIssueIdsFromUnknown(response.issueIds, ids);
    collectIssueIdsFromUnknown(record.issue_id, ids);
    collectIssueIdsFromUnknown(record.issue_ids, ids);

    for (const finding of response.findings ?? []) {
        if (!isRecord(finding)) { continue; }
        collectIssueIdsFromUnknown(finding.issueId, ids);
        collectIssueIdsFromUnknown(finding.issueIds, ids);
        collectIssueIdsFromUnknown(finding.issue_id, ids);
        collectIssueIdsFromUnknown(finding.issue_ids, ids);
    }

    return Array.from(ids.values());
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function truncateCodeForIdleRetry(code: string): string {
    if (code.length <= SERVER_IDLE_TRUNCATE_TO_CHARS) { return code; }
    return code.slice(0, SERVER_IDLE_TRUNCATE_TO_CHARS);
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null;
}

function toAbsoluteUrl(baseUrl: string, value: string): string {
    try {
        return new URL(value, baseUrl).toString();
    } catch {
        return value;
    }
}

function estimateRangeChars(lines: string[], start: number, end: number): number {
    let length = 0;
    for (let i = start; i < end; i++) {
        length += lines[i].length;
        if (i > start) { length += 1; } // newline
    }
    return length;
}

function splitRangeByChars(lines: string[], start: number, end: number, maxChars: number): LineRange[] {
    const ranges: LineRange[] = [];
    let cursor = start;

    while (cursor < end) {
        let next = cursor;
        let chars = 0;

        while (next < end) {
            const addition = (next === cursor ? 0 : 1) + lines[next].length;
            if ((chars + addition) > maxChars && next > cursor) { break; }
            chars += addition;
            next++;
            if (chars >= maxChars) { break; }
        }

        if (next === cursor) { next++; }
        ranges.push({ start: cursor, end: next, strategy: 'fixed' });
        cursor = next;
    }

    return ranges;
}

function isDeclarationBoundaryLine(line: string): boolean {
    if (!line.trim()) { return false; }
    return DECLARATION_PATTERNS.some(pattern => pattern.test(line));
}

function buildCodeChunks(code: string, options: Partial<ChunkBuildOptions> = {}): ScanCodeChunk[] {
    const chunkOptions: ChunkBuildOptions = {
        ...DEFAULT_CHUNK_BUILD_OPTIONS,
        ...options,
    };
    const chunkHardMaxChars = Math.max(1000, chunkOptions.chunkHardMaxChars);
    const chunkTargetChars = Math.max(1000, Math.min(chunkOptions.chunkTargetChars, chunkHardMaxChars));

    const lines = code.split(/\r?\n/);
    if (code.length <= chunkOptions.autoChunkThreshold || lines.length <= 1) {
        return [{
            index: 1,
            startLine: 1,
            endLine: lines.length,
            code,
            strategy: 'declaration',
        }];
    }

    const starts = new Set<number>([0]);
    for (let i = 1; i < lines.length; i++) {
        if (isDeclarationBoundaryLine(lines[i])) {
            starts.add(i);
        }
    }
    starts.add(lines.length);

    const orderedStarts = Array.from(starts).sort((a, b) => a - b);
    const declarationRanges: LineRange[] = [];
    for (let i = 0; i < (orderedStarts.length - 1); i++) {
        const start = orderedStarts[i];
        const end = orderedStarts[i + 1];
        if (start < end) {
            declarationRanges.push({ start, end, strategy: 'declaration' });
        }
    }

    if (declarationRanges.length === 0) {
        declarationRanges.push({ start: 0, end: lines.length, strategy: 'declaration' });
    }

    const normalizedRanges: LineRange[] = [];
    for (const range of declarationRanges) {
        const rangeChars = estimateRangeChars(lines, range.start, range.end);
        if (rangeChars > chunkHardMaxChars) {
            normalizedRanges.push(...splitRangeByChars(lines, range.start, range.end, chunkTargetChars));
        } else {
            normalizedRanges.push(range);
        }
    }

    const packedRanges: LineRange[] = [];
    let current: LineRange | undefined;
    for (const range of normalizedRanges) {
        if (!current) {
            current = { ...range };
            continue;
        }

        const combinedChars = estimateRangeChars(lines, current.start, range.end);
        if (combinedChars <= chunkHardMaxChars) {
            current.end = range.end;
            if (range.strategy === 'fixed') { current.strategy = 'fixed'; }
            continue;
        }

        packedRanges.push(current);
        current = { ...range };
    }
    if (current) { packedRanges.push(current); }

    if (packedRanges.length <= 1) {
        return [{
            index: 1,
            startLine: 1,
            endLine: lines.length,
            code,
            strategy: 'declaration',
        }];
    }

    return packedRanges.map((range, idx) => ({
        index: idx + 1,
        startLine: range.start + 1,
        endLine: range.end,
        code: lines.slice(range.start, range.end).join('\n'),
        strategy: range.strategy,
    }));
}

function buildIdleSplitChunks(code: string, depth: number): ScanCodeChunk[] {
    if (depth >= IDLE_SPLIT_MAX_DEPTH) { return []; }

    const lineCount = code.split(/\r?\n/).length;
    if (code.length < IDLE_SPLIT_MIN_CHARS || lineCount < IDLE_SPLIT_MIN_LINES) { return []; }

    const dynamicHardMax = Math.max(
        IDLE_SPLIT_MIN_HARD_MAX_CHARS,
        Math.min(CHUNK_HARD_MAX_CHARS, Math.floor(code.length / 2)),
    );
    const dynamicTarget = Math.max(
        IDLE_SPLIT_MIN_TARGET_CHARS,
        Math.min(dynamicHardMax - 200, Math.floor(dynamicHardMax * 0.7)),
    );

    const chunks = buildCodeChunks(code, {
        autoChunkThreshold: 0,
        chunkHardMaxChars: dynamicHardMax,
        chunkTargetChars: dynamicTarget,
    });

    return chunks.length > 1 ? chunks : [];
}

function remapLineNumber(
    line: number | undefined,
    lineOffset: number,
    chunkLineCount: number,
): number | undefined {
    if (typeof line !== 'number' || !Number.isFinite(line)) { return line; }
    const normalized = Math.max(1, Math.trunc(line));
    // Some backends may already report absolute line numbers; avoid double-offset in that case.
    if (normalized > (chunkLineCount + 5)) { return normalized; }
    return normalized + lineOffset;
}

function remapFindingLines(finding: ScanFinding, chunk: ScanCodeChunk): ScanFinding {
    const lineOffset = chunk.startLine - 1;
    const chunkLineCount = chunk.endLine - chunk.startLine + 1;
    return {
        ...finding,
        line: remapLineNumber(finding.line, lineOffset, chunkLineCount),
        endLine: remapLineNumber(finding.endLine, lineOffset, chunkLineCount),
    };
}

function findingKey(finding: ScanFinding): string {
    return [
        finding.severity ?? '',
        finding.title ?? '',
        finding.description ?? '',
        finding.suggestion ?? '',
        finding.line ?? '',
        finding.column ?? '',
        finding.endLine ?? '',
        finding.endColumn ?? '',
    ].join('|');
}

function mergeChunkResponses(chunks: ScanCodeChunk[], responses: ScanResponse[]): ScanResponse {
    const uniqueFindings: ScanFinding[] = [];
    const seen = new Set<string>();
    const issueIds = new Map<string, IssueIdentifier>();

    for (let i = 0; i < responses.length; i++) {
        const response = responses[i];
        const chunk = chunks[i];
        for (const issueId of collectIssueIdsFromResponse(response)) {
            issueIds.set(String(issueId), issueId);
        }

        for (const finding of response.findings ?? []) {
            const remapped = remapFindingLines(finding, chunk);
            const key = findingKey(remapped);
            if (!seen.has(key)) {
                seen.add(key);
                uniqueFindings.push(remapped);
            }
        }
    }

    const mergedIssueIds = Array.from(issueIds.values());
    const merged: ScanResponse = {
        ...(responses[0] ?? {}),
        findings: uniqueFindings,
        chunkCount: chunks.length,
    };

    if (mergedIssueIds.length > 0) {
        merged.issueId = mergedIssueIds[0];
        if (mergedIssueIds.length > 1) {
            merged.issueIds = mergedIssueIds;
        }
    }

    return merged;
}

function extractAsyncStatus(data: unknown): string | undefined {
    if (!isRecord(data)) { return undefined; }
    const status = data.status ?? data.state;
    return typeof status === 'string' ? status.trim().toLowerCase() : undefined;
}

function isPendingStatus(status: string): boolean {
    return ASYNC_PENDING_STATUSES.has(status);
}

function isSuccessStatus(status: string): boolean {
    return ASYNC_SUCCESS_STATUSES.has(status);
}

function isFailureStatus(status: string): boolean {
    return ASYNC_FAILURE_STATUSES.has(status);
}

function extractScanResponse(data: unknown): ScanResponse | undefined {
    if (!isRecord(data)) { return undefined; }

    const result = data.result;
    if (isRecord(result) && ('findings' in result || 'issueId' in result || 'error' in result || 'issueIds' in result)) {
        return result as ScanResponse;
    }

    if ('findings' in data || 'issueId' in data || 'error' in data || 'issueIds' in data) {
        return data as ScanResponse;
    }

    return undefined;
}

function extractPollUrl(
    requestUrl: string,
    data: unknown,
    headers: AxiosResponse<unknown>['headers'],
): string | undefined {
    const headerRecord = headers as Record<string, unknown> | undefined;
    const locationHeader = typeof headerRecord?.location === 'string'
        ? headerRecord.location
        : undefined;
    if (locationHeader) {
        return toAbsoluteUrl(requestUrl, locationHeader);
    }

    if (!isRecord(data)) { return undefined; }

    const urlFields = [data.pollUrl, data.statusUrl, data.resultUrl];
    for (const field of urlFields) {
        if (typeof field === 'string' && field.trim()) {
            return toAbsoluteUrl(requestUrl, field.trim());
        }
    }

    const jobRef = data.jobId ?? data.requestId ?? data.id;
    if (typeof jobRef === 'string' || typeof jobRef === 'number') {
        try {
            const u = new URL(requestUrl);
            const path = u.pathname.replace(/\/+$/, '');
            const scanPath = path.endsWith('/scan') ? path : `${path}/scan`;
            u.pathname = `${scanPath}/jobs/${encodeURIComponent(String(jobRef))}`;
            return u.toString();
        } catch {
            return undefined;
        }
    }

    return undefined;
}

function extractPollErrorMessage(data: unknown): string | undefined {
    if (!isRecord(data)) { return undefined; }
    const direct = data.error ?? data.message;
    if (typeof direct === 'string') { return direct; }
    if (isRecord(data.result) && typeof data.result.error === 'string') {
        return data.result.error;
    }
    return undefined;
}

async function pollScanResult(
    pollUrl: string,
    timeoutMs: number,
    base: AxiosRequestConfig,
    output: vscode.OutputChannel,
): Promise<ScanResponse> {
    const pollBudgetMs = Math.max(timeoutMs, MIN_POLL_WAIT_MS);
    const maxAttempts = Math.max(1, Math.ceil(pollBudgetMs / POLL_INTERVAL_MS));

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        if (attempt === 1 || attempt % 5 === 0) {
            output.appendLine(`[scan] Polling scan job (${attempt}/${maxAttempts})...`);
        }

        const response = await axios.get<unknown>(pollUrl, { ...base, timeout: timeoutMs });
        const status = extractAsyncStatus(response.data);
        const result = extractScanResponse(response.data);

        if (status && isFailureStatus(status)) {
            throw new Error(extractPollErrorMessage(response.data) ?? `Scan job failed (status=${status})`);
        }

        if (result && (!status || isSuccessStatus(status))) {
            return result;
        }

        if (!status && result) {
            return result;
        }

        if (attempt === maxAttempts) { break; }
        if (status && !isPendingStatus(status) && !isSuccessStatus(status)) {
            throw new Error(`Scan job returned unexpected status: ${status}`);
        }

        await sleep(POLL_INTERVAL_MS);
    }

    throw new Error(`Polling timeout after ${pollBudgetMs}ms`);
}

async function normalizeScanResponse(
    requestUrl: string,
    response: AxiosResponse<unknown>,
    timeoutMs: number,
    base: AxiosRequestConfig,
    output: vscode.OutputChannel,
): Promise<ScanResponse> {
    const status = extractAsyncStatus(response.data);
    const shouldPoll = response.status === 202 || (status ? isPendingStatus(status) : false);
    if (shouldPoll) {
        const pollUrl = extractPollUrl(requestUrl, response.data, response.headers);
        if (!pollUrl) {
            throw new Error('Scan accepted but backend did not provide a poll URL.');
        }
        output.appendLine(`[scan] Request accepted, polling result from ${pollUrl}`);
        return pollScanResult(pollUrl, timeoutMs, base, output);
    }

    const result = extractScanResponse(response.data);
    if (result) {
        return result;
    }

    throw new Error(`Unexpected scan response format (HTTP ${response.status})`);
}

function buildFallbackUrl(apiUrl: string): string | undefined {
    try {
        const u = new URL(apiUrl);
        const p = u.pathname.replace(/\/+$/, '');
        if (p.endsWith('/scan')) { return undefined; }
        if (p.endsWith('/code-security')) {
            u.pathname = `${p}/scan`;
            return u.toString();
        }
    } catch { /* ignore */ }
    return undefined;
}

const SKIP_PATH_SEGMENTS = ['dist', 'node_modules', 'vendor', '.git'];
const SKIP_EXTENSIONS = ['.lock'];

export function shouldSkipFile(filePath: string): string | undefined {
    const normalized = filePath.replace(/\\/g, '/');
    for (const seg of SKIP_PATH_SEGMENTS) {
        if (normalized.includes(`/${seg}/`) || normalized.startsWith(`${seg}/`)) {
            return `路徑包含 ${seg}/`;
        }
    }
    for (const ext of SKIP_EXTENSIONS) {
        if (normalized.endsWith(ext)) {
            return `副檔名為 ${ext}`;
        }
    }
    return undefined;
}

export function loadConfig(): ScanConfig {
    const c = vscode.workspace.getConfiguration(CONFIG_SECTION);

    return {
        apiUrl: (c.get<string>('apiUrl') ?? DEFAULT_API_URL ?? '').trim(),
        timeoutMs: c.get<number>('requestTimeoutMs', DEFAULT_TIMEOUT_MS),
        allowSelfSignedCert: c.get<boolean>('allowSelfSignedCert', false),
        concurrency: c.get<number>('workspaceScanConcurrency', 3),
        includePatterns: c.get<string[]>('includePatterns', [
            '**/*.{ts,js,tsx,jsx,vue,py,php,java,go,rb,rs,c,cpp,h,hpp,cs,swift,kt,scala,sh}',
        ]),
        excludePatterns: c.get<string[]>('excludePatterns', [
            '**/node_modules/**', '**/dist/**', '**/build/**', '**/.git/**',
            '**/vendor/**', '**/*.lock', '**/*.min.js', '**/*.min.css',
            '**/package-lock.json', '**/yarn.lock', '**/pnpm-lock.yaml',
        ]),
    };
}

export async function getGitRemoteUrl(): Promise<string> {
    const ext = vscode.extensions.getExtension('vscode.git');
    if (ext && !ext.isActive) { await ext.activate(); }
    return ext?.exports?.getAPI?.(1)?.repositories?.[0]?.state.remotes?.[0]?.fetchUrl || 'unknown';
}

export interface ScanPayload {
    code: string;
    fileName: string;
    remoteUrl: string;
    user: string;
}

export async function sendScanRequest(
    payload: ScanPayload,
    config: ScanConfig,
    output: vscode.OutputChannel,
): Promise<ScanResponse> {
    const { apiUrl, timeoutMs, allowSelfSignedCert } = config;
    const resolvedApiUrl = apiUrl.trim();
    if (!resolvedApiUrl) {
        throw new Error(`未設定掃描 API URL，請設定 ${CONFIG_SECTION}.apiUrl 或環境變數 DEFAULT_API_URL。`);
    }

    const timeout1 = Math.max(1000, timeoutMs);
    const timeout2 = Math.min(timeout1 * RETRY_TIMEOUT_MULTIPLIER, MAX_TIMEOUT_MS);

    const base: AxiosRequestConfig = {
        httpsAgent: allowSelfSignedCert ? new https.Agent({ rejectUnauthorized: false }) : undefined,
    };

    const post = async (url: string, timeout: number, body: ScanPayload = payload): Promise<ScanResponse> => {
        output.appendLine(`[scan] POST ${url} (timeout=${timeout}ms, file=${body.fileName}, code=${body.code.length} chars)`);
        const response = await axios.post<unknown>(url, body, { ...base, timeout });
        return normalizeScanResponse(url, response, timeout, base, output);
    };

    const isServerIdleError = (err: unknown): boolean => {
        if (!axios.isAxiosError(err)) { return false; }
        const responseData = err.response?.data;
        const errorText = isRecord(responseData) && typeof responseData.error === 'string'
            ? responseData.error.toLowerCase()
            : '';
        return err.response?.status === 500 && errorText.includes(SERVER_IDLE_TIMEOUT_HINT);
    };

    const isTransientGatewayError = (err: unknown): boolean => {
        if (!axios.isAxiosError(err)) { return false; }
        const status = err.response?.status;
        return typeof status === 'number' && TRANSIENT_GATEWAY_STATUSES.has(status);
    };

    const splitAndRetry = async (
        url: string,
        body: ScanPayload,
        depth: number,
        reason: string,
    ): Promise<ScanResponse | undefined> => {
        const splitChunks = buildIdleSplitChunks(body.code, depth);
        if (splitChunks.length <= 1) { return undefined; }

        output.appendLine(`[scan] ${reason}, splitting into ${splitChunks.length} smaller chunks (depth=${depth + 1})...`);
        const splitResponses: ScanResponse[] = [];

        for (const splitChunk of splitChunks) {
            output.appendLine(`[scan] Split ${splitChunk.index}/${splitChunks.length}: lines ${splitChunk.startLine}-${splitChunk.endLine}, ${splitChunk.code.length} chars (${splitChunk.strategy})`);
            const splitPayload: ScanPayload = {
                ...body,
                code: splitChunk.code,
            };
            splitResponses.push(await tryWithRetry(url, splitPayload, depth + 1));
        }

        const merged = mergeChunkResponses(splitChunks, splitResponses);
        output.appendLine(`[scan] Split merge completed (${merged.findings?.length ?? 0} unique findings).`);
        return merged;
    };

    const tryReducedCodeRetry = async (url: string, body: ScanPayload): Promise<ScanResponse | undefined> => {
        if (body.code.length <= SERVER_IDLE_TRUNCATE_THRESHOLD) { return undefined; }
        const reducedCode = truncateCodeForIdleRetry(body.code);
        if (reducedCode.length >= body.code.length) { return undefined; }
        output.appendLine(`[scan] Backend session idle timeout, retrying with reduced code (${reducedCode.length}/${body.code.length} chars)...`);
        return post(url, timeout2, { ...body, code: reducedCode });
    };

    const recoverAfterRetryError = async (
        url: string,
        body: ScanPayload,
        depth: number,
        retryErr: unknown,
    ): Promise<ScanResponse> => {
        if (isServerIdleError(retryErr)) {
            const splitRecovered = await splitAndRetry(url, body, depth, 'Idle timeout persists');
            if (splitRecovered) { return splitRecovered; }
            const reducedRecovered = await tryReducedCodeRetry(url, body);
            if (reducedRecovered) { return reducedRecovered; }
        }

        if (isTransientGatewayError(retryErr)) {
            const status = (axios.isAxiosError(retryErr) ? retryErr.response?.status : undefined) ?? 'unknown';
            const splitRecovered = await splitAndRetry(url, body, depth, `Gateway ${status} persists`);
            if (splitRecovered) { return splitRecovered; }
        }

        throw retryErr;
    };

    const retryLongTimeout = async (
        url: string,
        body: ScanPayload,
        depth: number,
        message: string,
        delayMs = 0,
    ): Promise<ScanResponse> => {
        if (delayMs > 0) {
            await sleep(delayMs);
        }
        output.appendLine(message);
        try {
            return await post(url, timeout2, body);
        } catch (retryErr: unknown) {
            return recoverAfterRetryError(url, body, depth, retryErr);
        }
    };

    const tryWithRetry = async (
        url: string,
        body: ScanPayload = payload,
        depth = 0,
    ): Promise<ScanResponse> => {
        try {
            return await post(url, timeout1, body);
        } catch (err: unknown) {
            if (!axios.isAxiosError(err)) { throw err; }

            if (isServerIdleError(err)) {
                return retryLongTimeout(
                    url,
                    body,
                    depth,
                    '[scan] Backend session idle timeout, retrying...',
                    SERVER_IDLE_RETRY_DELAY_MS,
                );
            }

            if (isTransientGatewayError(err)) {
                const status = err.response?.status ?? 'unknown';
                return retryLongTimeout(
                    url,
                    body,
                    depth,
                    `[scan] Gateway ${status} from backend, retrying...`,
                    GATEWAY_RETRY_DELAY_MS,
                );
            }

            if (err.code === 'ECONNABORTED' && timeout2 > timeout1) {
                return retryLongTimeout(
                    url,
                    body,
                    depth,
                    `[scan] Client timeout, retrying (timeout=${timeout2}ms)`,
                );
            }

            throw err;
        }
    };

    const scanWithUrl = async (url: string): Promise<ScanResponse> => {
        const chunks = buildCodeChunks(payload.code);
        if (chunks.length <= 1) {
            return tryWithRetry(url, payload);
        }

        output.appendLine(`[scan] Auto chunking enabled (${chunks.length} chunks).`);
        const responses: ScanResponse[] = [];

        for (const chunk of chunks) {
            output.appendLine(`[scan] Chunk ${chunk.index}/${chunks.length}: lines ${chunk.startLine}-${chunk.endLine}, ${chunk.code.length} chars (${chunk.strategy})`);
            const chunkPayload: ScanPayload = {
                ...payload,
                code: chunk.code,
            };
            responses.push(await tryWithRetry(url, chunkPayload));
        }

        const merged = mergeChunkResponses(chunks, responses);
        output.appendLine(`[scan] Chunk merge completed (${merged.findings?.length ?? 0} unique findings).`);
        return merged;
    };

    try {
        return await scanWithUrl(resolvedApiUrl);
    } catch (err: unknown) {
        const fallback = buildFallbackUrl(resolvedApiUrl);
        if (fallback && axios.isAxiosError(err) && err.response?.status === 404) {
            output.appendLine(`[scan] 404, trying fallback: ${fallback}`);
            return scanWithUrl(fallback);
        }
        throw err;
    }
}

export function formatAxiosError(error: unknown): string {
    if (!axios.isAxiosError(error)) {
        return error instanceof Error ? error.message : '未知錯誤';
    }

    const status = error.response?.status;
    const code = error.code;
    const message = error.message;
    const responseError = typeof error.response?.data?.error === 'string'
        ? error.response.data.error : undefined;

    return [status ? `HTTP ${status}` : undefined, code, message, responseError]
        .filter(Boolean).join(' | ');
}
