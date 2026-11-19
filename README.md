# Purple Maple Shared DevSecOps Workflows (`pm-secops-workflows`)

紫楓（Purple Maple / `ai-purplemaple.com`）全專案共用的 GitHub Actions 零機密資安守門與無金鑰 OIDC 部署工作流模板庫。

## 包含之共用工作流 (Reusable Workflows)

1. **`.github/workflows/reusable-secops.yml`**：
   - **Stage 1**：機密金鑰掃描、內部開發路徑外洩攔截、敏感憑證檔與 `>5 MiB` 容量檢查、GitHub Actions 40 字元 SHA 供應鏈稽核。
   - **Stage 2**：Python `Bandit` 高危靜態安全掃描 (SAST) 與 Node.js `npm audit` 生產依賴弱點掃描 (SCA)。
   - **Stage 3**：專案自動化單元測試、Docker 映像建置、容器敏感路徑暴露黑盒預檢（確認 `/server.py`、`/.env`、`/Dockerfile` 阻擋）與 **Aqua Trivy** 容器重大漏洞掃描。
2. **`.github/workflows/reusable-cloudrun-wif.yml`**：
   - 透過 Google Cloud **Workload Identity Federation (OIDC)** 無金鑰部署至 Cloud Run（強制套用專屬最小權限 Service Account 與 `max-instances` 防刷流上限），並於部署後自動驗證線上 `Strict-Transport-Security`、`X-Content-Type-Options: nosniff` 與敏感檔阻擋狀態。
3. **`.github/workflows/scheduled-security-drift.yml`**：
   - 每週自動巡檢旗下 10 大正式網域之 HTTPS 安全標頭與邊緣設定漂移。

## 呼叫範例（各專案 `.github/workflows/secops.yml` 僅需 15 行）

```yaml
name: DevSecOps Gate

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  security:
    uses: tbpfs/pm-secops-workflows/.github/workflows/reusable-secops.yml@main
    with:
      python_sast: true
      docker_scan: true
      public_web_gate: true
      test_command: "python3 -m unittest discover -s tests -v"
```
