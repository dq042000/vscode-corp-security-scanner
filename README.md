# Corp Security Scanner

公司內部 AI 資安弱掃 VS Code 擴充套件。  
可針對單一檔案或整個專案進行弱點掃描，並將結果同步到 GitLab Issue。

## 環境需求

- Node.js 18+（建議使用 LTS）
- npm
- Visual Studio Code 1.109.0 以上

## 功能特色

- **單檔掃描**：在編輯器右鍵直接掃描目前檔案。
- **專案掃描**：從檔案總管右鍵對整個 workspace 批次掃描。
- **自動切塊掃描**：大檔案會依函式/類別邊界分塊，必要時再細分，降低 timeout 風險。
- **重試與容錯**：針對 timeout、`session.idle`、502/503/504 進行重試與降階處理。
- **非同步輪詢**：後端回傳 202/pending 狀態時自動 polling 直到完成。
- **編輯器診斷**：掃描結果會同步顯示為 VS Code Diagnostics（workspace 掃描）。

## 使用方式

### 掃描目前檔案

1. 在 VS Code 開啟程式碼檔案
2. 右鍵選單執行 **🛡️ 執行 AI 資安弱掃（當前檔案）**

### 掃描整個專案

1. 在 Explorer 對專案右鍵
2. 執行 **🛡️ 執行 AI 資安弱掃（整個專案）**

## 擴充套件設定

本套件提供以下設定（`settings.json`）：

- `corpSecurityScanner.apiUrl`  
  掃描 API 位址（必要）。若未設定會無法掃描。

- `corpSecurityScanner.requestTimeoutMs`  
  API 請求逾時毫秒數（預設：`120000`）。

- `corpSecurityScanner.allowSelfSignedCert`  
  是否允許自簽憑證（預設：`false`）。

- `corpSecurityScanner.workspaceScanConcurrency`  
  專案掃描併發數（預設：`3`，範圍 1~10）。

- `corpSecurityScanner.includePatterns`  
  專案掃描包含檔案規則（glob）。

- `corpSecurityScanner.excludePatterns`  
  專案掃描排除檔案規則（glob）。

## 設定範本

### `.env` 範例（建議）

```env
DEFAULT_API_URL=https://your-internal-domain.example.com/code-security/scan
```

### `settings.json` 範例

```json
{
  "corpSecurityScanner.apiUrl": "https://your-internal-domain.example.com/code-security/scan",
  "corpSecurityScanner.requestTimeoutMs": 120000,
  "corpSecurityScanner.allowSelfSignedCert": false,
  "corpSecurityScanner.workspaceScanConcurrency": 3
}
```

> 建議將實際內網 URL 放在私有環境（例如 `.env`、CI/CD 變數或個人設定），不要提交到公開倉庫。

## 編譯與安裝（VS Code）

### 1) 安裝相依套件

```bash
npm install
```

### 2) 編譯 Extension

```bash
npm run package
```

### 3) 打包成 VSIX

```bash
npx @vscode/vsce package
```

完成後會在專案根目錄產生 `.vsix` 檔案（例如：`corp-security-scanner-0.0.1.vsix`）。

### 4) 在 VS Code 安裝

方式 A（UI）：
1. 開啟 VS Code
2. 執行命令：`Extensions: Install from VSIX...`
3. 選擇剛剛產生的 `.vsix` 檔案

方式 B（CLI）：
```bash
code --install-extension corp-security-scanner-0.0.1.vsix
```

## 注意事項

- 掃描結果與建立 Issue 數量最終以 **GitLab 實際建立結果** 為準。
- 若後端負載高或網路不穩，仍可能出現延遲或重試。
- 若單檔過大且多次失敗，建議先針對可疑區塊選取後掃描。

## 開發與測試

```bash
npm run lint
npm run compile
npm test
```

## 版本

- `0.0.1`：初版功能（單檔/專案掃描、重試、切塊、Issue 同步）
