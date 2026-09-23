# IFF Witness Example

[English](README.md) · **繁體中文**

**查核有依據，解說有憑據。**

在筆電上執行 Witness，比對 x402 付款要求與 [IFF](https://ifandonlyif.io) 的觀測證據；也可以接上 0G 解讀已核對的結果，再下載證據包、本機重新驗證。這份公開範例獨立運作，不會啟動 IFF 的正式監控服務。

**先在本機跑起來就好。演練不需要部署、API key、錢包、資料庫、Docker，也不用安裝 Node.js。**

## Apostille 範例：替證據包加上來源簽章

**[直接試用線上 Apostille 範例](https://iff-witness-production.up.railway.app/apostille.html)**，不用安裝。可在瀏覽器產生一組對應的測試檔案，下載後查驗原件，或換成刻意修改的檔案觀察差異。

啟動 Witness 後，開啟 **[本機 Apostille 範例](http://127.0.0.1:8094/apostille.html)**。用內建演練資料或自己的 Witness 檔案建立本機簽章，在原件加一個空白，觀察「簽章仍有效、原件比對不符」，再下載兩份檔案交給另一個人離線查驗。

不需帳號、API key、錢包、託管簽發或 0G 額度。結果維持 `producer_only`、issuer 信任未知，也不會提升內層 IFF／0G／AgenticID 證據的驗證狀態。詳見[網頁與命令列操作指引](examples/APOSTILLE.md)。

## 1. 安裝必要工具

| 工具 | 什麼時候需要 | 安裝方式 |
|---|---|---|
| Git | 下載、更新這份 repo | [Git 官方安裝頁](https://git-scm.com/install/) |
| Go | 啟動網頁服務 | [Go 官方安裝教學](https://go.dev/doc/install)；使用 **1.26.6 或更新版本**，以符合專案指定的工具鏈 |
| Node.js + npm | 只有離線 CLI 驗證、修改前端或使用 `npm start` 才需要 | [Node.js 官方下載頁](https://nodejs.org/en/download)；選仍受支援的 LTS，本文指令要求 **22.9.0 以上** |

選擇符合你的作業系統與處理器的安裝包。安裝完後，重新開啟 macOS/Linux 的終端機，或 Windows 的 PowerShell，確認：

```sh
git --version
go version
```

兩個指令都應顯示版本號。[go.mod](go.mod) 的最低 Go 版本是 1.25.0，指定工具鏈為 1.26.6。若已安裝較舊版本且開啟自動工具鏈選擇，Go 可能在首次執行時下載指定版本；詳見 [Go 工具鏈說明](https://go.dev/doc/toolchain)。第一次下載 repo、Go 套件與工具鏈需要網路。

## 2. 下載並啟動

在你平常存放專案的資料夾中，依序執行以下三行。macOS/Linux 終端機與 Windows PowerShell 都可使用：

```sh
git clone https://github.com/ifandonlyif-io/iff-witness-example.git
cd iff-witness-example
go run ./cmd/witness
```

第一次下載與編譯可能需要一段時間。看到下列訊息，就表示服務開始監聽；請讓這個終端機持續開著：

```text
IFF Witness is listening on 127.0.0.1:8094 (rehearsal is the default)
```

用目前版本的瀏覽器打開 **[http://127.0.0.1:8094](http://127.0.0.1:8094)**。介面是繁體中文。不要直接點開 `web/index.html`：這個頁面需要本機 Go 服務配合運作。

網頁檔案與[公開 endpoint 範例](examples/README.md) 已包含在執行檔中。這條啟動路線不需要建立 `.env`、安裝 JavaScript 套件或指定範例路徑。

- **停止服務：**回到執行服務的終端機，按 `Ctrl+C`。
- **下次啟動：**進入 `iff-witness-example` 資料夾，再執行 `go run ./cmd/witness`。
- **換一台筆電：**在新電腦重複安裝與 clone 步驟即可，不要直接複製另一台的私鑰或 `.env`。

## 3. 先確認演練正常，不需要金鑰

保留「**演練資料**」模式，依序試一次：

1. 選「**原始範例**」，按「**執行查核**」，應看到 `consistent`。
2. 改選「**模擬更換收款地址**」再執行，應看到 `diverged`。
3. 按「**修改判定並驗證**」：原簽章可以仍有效，但外層結果與簽署內容的比對應出現不符。
4. 按「**還原原始證據**」，再按「**下載證據包**」；用「**匯入證據包重新驗證**」重新核對存下來的檔案。

演練使用模擬觀測、真實的本機 Ed25519 演練簽章，以及固定解說文字。**不會連外呼叫服務，也不會消耗 0G 額度。** 沒有 0G 或 AgenticID 證明的項目會顯示「未驗證」，這是預期結果，不是安裝失敗。

## 4. 選用：接上真實 IFF + 0G

只想體驗介面或驗證器，可以跳過這一節。真實推理可能消耗付費 Router 額度；Witness 本身不會向 x402 endpoint 付款。

1. 依 [0G 官方 Router 入門教學](https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/quickstart)，準備一把有可用額度的 **mainnet Router 推理 API key**。主網控制台是 [pc.0g.ai](https://pc.0g.ai)。測試網金鑰／餘額，以及 Direct／Advanced 的供應商餘額，與此範例使用的主網 Router 是分開的；見 [Router 說明](https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/overview)。
2. 保持本機服務執行，點頁尾「**金鑰與驗證設定**」，或直接開啟[本機設定頁](http://127.0.0.1:8094/settings.html)。
3. 將 Router API key 貼入「**0G Router API 金鑰**」，按「**儲存並啟用**」。不要填錢包私鑰、IFF 簽章私鑰或管理金鑰。「IFF 收據公鑰指紋」是選填的公開信任設定，不是第二把秘密金鑰。
4. 切回 Demo 分頁，手動選擇「**真實 IFF + 0G**」、選擇情境，再按「**執行查核**」。
5. 分別檢視 IFF 與 0G 的核對結果，再下載證據包。真實判定取決於當下的公開證據，不保證一定是 `consistent`。

儲存金鑰本身不會發送推理，也不會檢查餘額。透過設定頁輸入的金鑰只留在服務的記憶體，不寫入 `.env`、不放進證據包；重新啟動後需再輸入。若原本透過環境變數提供金鑰，重啟會恢復該環境設定。

真實模式會先核對 IFF 收據，通過後才呼叫 0G。預設每個執行中的服務最多 **30 次推理嘗試**，Router 失敗的嘗試也計入。這不是永久支出上限：重啟會重設次數，因此也應在供應商端設定支出控制。缺少證明或未獨立指定信任身份時，仍會顯示「未驗證」；Router 的自我回報不等於獨立證明。

## 5. 選用：不用啟動服務，也能驗證證據包

先安裝第 1 節的 Node.js + npm。在 repo 根目錄確認版本、安裝套件，再驗證隨附範例：

```sh
node --version
npm --version
npm ci
npm run verify -- examples/agentic-demo-bundle.json examples/trusted-policy.json
```

這份隨附檔案是**使用公開測試金鑰自行簽署的測試向量**，不是正式 Sealed Sandbox 核發的證明。指令應以退出碼 0 結束，但過期的 IFF 收據、未指定信任身份等項目可能顯示警告或未驗證。套件安裝完成後，驗證指令可以離線執行，不需要 Go 服務、API key 或錢包。

另外執行刻意竄改的版本：

```sh
npm run verify -- examples/agentic-demo-bundle-tampered.json examples/trusted-policy.json
```

預期 `agentic-bundle-response` 不通過，退出碼是 **1**。這次「失敗」代表驗證器正確抓到竄改。

若要驗證自己的下載檔，把下列路徑換成你的證據包與透過獨立可信來源取得的信任政策：

```sh
npm run verify -- /path/to/bundle.json /path/to/trusted-policy.json
```

退出碼 **0** 只表示「沒有失敗項目」，**不代表每項聲明都已驗證**；**1** 表示至少一項不通過，**2** 表示輸入無法讀取或格式錯誤。不要直接把待驗檔案內的公鑰當成可信身份。隨附政策含測試用 AgenticID 指紋，不是正式身份的信任政策；詳見[離線驗證與信任設定](docs/GUIDE.md#download-and-verify-offline)。

## 6. 更新版本，或產生執行檔

先停止服務。在 repo 根目錄、沒有衝突的本機修改時執行：

```sh
git pull --ff-only
go run ./cmd/witness
```

若 Git 提示本機修改或歷史分歧，先保留並處理自己的變更，不要為了更新而直接重設檔案。一般 Go 啟動路線使用 repo 已附的網頁建置結果，不需要執行 `npm ci`。

若不想每次用 `go run`，可以編譯成執行檔。

macOS/Linux：

```sh
go build -o bin/witness ./cmd/witness
./bin/witness
```

Windows PowerShell：

```powershell
go build -o bin/witness.exe ./cmd/witness
.\bin\witness.exe
```

執行檔包含介面與預設範例。請在目標筆電編譯，或使用對應作業系統／處理器的版本；macOS 執行檔不能直接拿到 Windows 執行。執行時的金鑰與信任設定不會被包進執行檔。

## 7. 選用：修改前端，或使用 `.env`

只有需要修改介面，或想從設定檔載入參數時，才需要走這條路。**仍然需要 Go**：`npm start` 啟動的是同一個 Go 服務。

1. 先停止已執行的服務，並安裝第 1 節的 Node.js + npm。
2. 在 repo 根目錄安裝套件、重新建置網頁：

   ```sh
   npm ci
   npm run build
   ```

3. 若要使用設定檔，**只有在 `.env` 不存在時**，才把 `.env.example` 複製為 `.env`。這一步可省略；使用本機金鑰設定頁就不必把 Router key 存入檔案。
4. 啟動：

   ```sh
   npm start
   ```

`npm start` 會讀取選填的 `.env`；`go run ./cmd/witness` 與編譯後的執行檔只讀取程序的環境變數。修改 `.env` 後要重啟。修改 `client/` 後，要執行 `npm run build` 並重啟服務，不會自動更新前端。不要提交 `.env`，也不要把它和證據包一起分享。

修改後可執行：

```sh
npm test
go test ./...
go vet ./...
```

完整檢查清單見 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 常見問題

| 遇到的狀況 | 檢查方式 |
|---|---|
| 找不到 `git` 或 `go` | 完成安裝、重開終端機，再確認版本號。 |
| Go 工具鏈／套件下載失敗 | 檢查網路、代理設定與 `go.mod` 指定的版本；不要透過降低模組版本或關閉驗證來繞過。 |
| `go.mod file not found` | 先進入含有 `go.mod` 的 `iff-witness-example` 根目錄再執行。 |
| `address already in use` | 停止另一個服務實例，或依下方指令更換 port。 |
| 網頁無法連線 | 確認服務終端機仍開著；網址應是 `http://127.0.0.1:8094`，不是 HTTPS，也不是直接開啟 HTML。 |
| 真實模式仍無法選擇 | 儲存 Router key 後切回 Demo 分頁。若顯示未設定範例，先更新 repo，再檢查是否設定了錯誤的 `WITNESS_EXAMPLE_FILE`。 |
| 設定頁回傳 403 | 設定頁只允許直接本機連線；不要經公開網址、tunnel 或反向代理開啟。公開部署需使用平台的秘密設定。 |
| `npm start` 不認得 `--env-file-if-exists` | 將 Node.js 更新為仍受支援的 LTS，至少 22.9.0；見[參數文件](https://nodejs.org/api/cli.html#--env-file-if-existsfile)。 |
| HTTP 429／暫時次數限制 | 至少等 60 秒再試；錯誤的真實模式密碼也會計入限流。 |
| 推理嘗試次數用完 | 先核對使用量與供應商支出限制。預設每次程序啟動為 30 次；不要把重啟當成費用控管方式。 |
| IFF／0G 暫時不可用、`stale` 或「未驗證」 | 可能是外部服務、資料時效或身份／證明限制，不一定是安裝錯誤。查看各項訊息，不要關閉簽章驗證。 |

需要換 port 時，先停止服務，再依你的終端機選擇**其中一組**：

macOS/Linux：

```sh
WITNESS_LISTEN_ADDR=127.0.0.1:18094 go run ./cmd/witness
```

Windows PowerShell：

```powershell
$env:WITNESS_LISTEN_ADDR = "127.0.0.1:18094"
go run ./cmd/witness
```

接著開啟 [http://127.0.0.1:18094](http://127.0.0.1:18094)。PowerShell 的環境變數會留在目前工作階段；要恢復預設 port，將其改回 `127.0.0.1:8094`，或開啟新的終端機。

## 功能邊界與進階文件

**條件一致不等於付款安全；推理簽章不等於答案正確。** Witness 不宣稱 IFF 的外部觀測在 TEE 內執行。演練與隨附的 AgenticID 測試向量，都不是已完成真實 0G 整合的證據。

依這份 README 操作，**不需要 Railway 或其他代管平台**。公開部署是另一件事：設定頁只開放本機、Router key 與次數額度由服務共用，公開的真實模式應加上密碼保護。對外開放前請讀[部署指南](docs/GUIDE.md#isolation-and-deployment)，不要只把監聽地址改成 `0.0.0.0`。

- [完整技術教學與環境設定](docs/GUIDE.md)
- [選用 AgenticID／Sealed Sandbox 整合](agentic/README.md)
- [原始碼來源](PROVENANCE.md) · [範例來源](examples/README.md) · [測試紀錄與尚未驗證的整合](QA.md)
- [0G 呼叫實作](compute.go) · [證明驗證](proofs.go) · [瀏覽器驗證器](client/verify.mjs)
- [MIT License](LICENSE) · [第三方授權](docs/licenses/README.md) · [安全回報](SECURITY.md)

以 [IFF](https://ifandonlyif.io) 的獨立觀測證據為基礎打造。Copyright (c) 2024 [IfAndOnlyIf.io](https://ifandonlyif.io)。
