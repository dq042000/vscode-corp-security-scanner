export interface ScanFinding {
    line?: number;
    column?: number;
    endLine?: number;
    endColumn?: number;
    severity?: string;
    title?: string;
    description?: string;
    suggestion?: string;
    issueId?: number | string;
    issueIds?: Array<number | string>;
}

export interface ScanResponse {
    issueId?: number | string;
    issueIds?: Array<number | string>;
    chunkCount?: number;
    findings?: ScanFinding[];
    error?: string;
    [key: string]: unknown;
}

export interface FileScanResult {
    filePath: string;
    status: 'success' | 'failed' | 'skipped' | 'cancelled';
    response?: ScanResponse;
    error?: string;
}

export interface ScanConfig {
    apiUrl: string;
    timeoutMs: number;
    allowSelfSignedCert: boolean;
    concurrency: number;
    includePatterns: string[];
    excludePatterns: string[];
}
