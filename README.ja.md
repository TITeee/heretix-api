# Heretix API

PostgreSQLベースのシンプルかつ高速な脆弱性管理APIです。**OSV**・**NIST NVD**・**CISA KEV**・**EPSS**・**Oracle Linux ELSA**・**ベンダーセキュリティアドバイザリ**などのデータを収集し、正規化されたマスターテーブルを通じて効率的な検索を提供します。

## 特徴

- **マルチソース**: OSV (Open Source Vulnerabilities)・NIST NVD (CVE)・Oracle Linux ELSA (OVAL XML)・ベンダーアドバイザリ（Fortinet / Palo Alto Networks / Cisco PSIRT 等）に対応
- **マルウェア検知**: OSV の `MAL-YYYY-NNNN` エントリ（悪意あるパッケージ）を [ossf/malicious-packages](https://github.com/ossf/malicious-packages) からインポートし、脆弱性検索エンドポイントで検索可能
- **重複排除**: `Vulnerability` マスターテーブルが CVE ID をキーにソース間の重複を吸収
- **CPE エイリアス対応**: NVD の CPE product 名変更（ベンダー買収等）に追従する `src/config/product-aliases.ts` で検索精度を維持
- **リスク評価値**: CISA KEV（悪用実績フラグ）・EPSS（悪用予測スコア）を脆弱性に紐づけ
- **シンプル**: PostgreSQLのみで動作（Redis不要）。Docker Compose によるデプロイにも対応
- **高速検索**: 正規化されたバージョン番号による整数比較で高速な範囲検索を実現
- **スケーラブル**: 生データをJSONBで保存し、検索用フィールドを正規化
- **RESTful API**: Fastifyベースの軽量で高速なAPIサーバー
- **NVD全件ミラー**: NVD全CVE（約24万件）のローカルミラーに対応（差分更新も可能）
- **OSV差分更新**: `CollectionJob` で最終実行日時を管理し、変更があったエントリのみを処理する差分更新に対応

## 技術スタック

- **Runtime**: Node.js
- **Framework**: Fastify (高速なWebフレームワーク)
- **ORM**: Prisma (型安全なデータベースアクセス)
- **Database**: PostgreSQL 15+ (ローカル/リモート対応)
- **Language**: TypeScript
- **Logging**: Pino (構造化ログ)
- **Validation**: Zod (スキーマ検証)

## セットアップ

### 1. 依存関係のインストール

```bash
pnpm install
```

### 2. PostgreSQLの準備

既存のPostgreSQLを使用するか、新規にインストールしてください。

#### ローカルPostgreSQLの場合:
```bash
# PostgreSQL 15以上がインストールされていることを確認
psql --version

# データベース作成
createdb vulndb
```

#### リモートPostgreSQLの場合:
- Supabase
- Neon
- Railway
- AWS RDS
などのサービスが利用可能

### 3. 環境変数の設定

`.env` ファイルを編集してDATABASE_URLを設定:

```env
DATABASE_URL="postgresql://postgres:password@localhost:5432/vulndb?schema=public"
PORT=3000
NODE_ENV=development
API_KEY=your-api-key-here   # Required. Requests without x-api-key header return 401
NVD_API_KEY=                # Optional. Relaxes NVD rate limit from 10 → 50 req/min
```

### 4. データベースマイグレーション

```bash
pnpm db:migrate
```

### 5. 開発サーバー起動

```bash
pnpm dev
```

サーバーは http://localhost:5000 で起動します。

> **開発時のインポートスクリプト**: `pnpm import:*` コマンドはコンパイル済みの `dist/` を参照します。`pnpm dev` のみで起動している場合（ビルドなし）は、`pnpm exec tsx` で直接実行してください：
> ```bash
> pnpm exec tsx src/scripts/import-osv.ts update npm
> pnpm exec tsx src/scripts/import-nvd.ts update
> ```

## データベース管理

### Prisma Studio
データベースをGUIで確認・編集できます。
```bash
pnpm db:studio
```
ブラウザで http://localhost:5555 が開きます。

### ER図の生成
データベーススキーマのER図を生成できます（Mermaid形式）。
```bash
pnpm db:erd
```
生成されたER図は `docs/erd.md` に保存されます。

## インポートステータス ダッシュボード

`/dashboard` にアクセスすると、インポート状況を確認できる Web UI が表示されます（認証不要）。

```
GET /dashboard
```

表示内容:
- **レコード数** — NVD / OSV / KEV / Advisory テーブルの総件数
- **インポートステータステーブル** — ソースごとの最新 `CollectionJob`（ステータスバッジ・最終完了日時・追加/更新件数・エラーメッセージ）
- **OSV エコシステム一覧** — DB にインポート済みのエコシステム名バッジ

60 秒ごとに自動リフレッシュ。JSON での取得も可能:

```
GET /api/v1/import-status
```

例: `http://localhost:5000/dashboard`

---

## API エンドポイント

### Health Check
サーバーの状態を確認します。
```
GET /health
```

**レスポンス例:**
```json
{
  "status": "ok",
  "timestamp": "2025-01-18T12:00:00.000Z"
}
```

### 脆弱性検索（単体）
指定されたパッケージとバージョンに影響する脆弱性を検索します。OSV・NVD・ベンダーアドバイザリテーブルを並行検索し、マスターテーブルで重複排除した結果を返します。
```
GET /api/v1/vulnerabilities/search
```

**クエリパラメータ:**
- `package` (必須): パッケージ名またはプロダクト名 (例: `lodash`, `FortiOS`)
- `version` (必須): バージョン (例: `4.17.20`, `7.4.3`)
- `ecosystem` (必須): エコシステムまたはベンダー (例: `npm`, `PyPI`, `Go`, `composer`, `fortinet`)
- `severity` (オプション): 深刻度フィルター (配列)
- `limit` (オプション): 結果の最大数 (デフォルト: 500, 最大: 500)
- `offset` (オプション): オフセット (デフォルト: 0)

**リクエスト例:**
```bash
# OSV/NVD（パッケージ）
curl "http://localhost:3001/api/v1/vulnerabilities/search?package=lodash&version=4.17.20&ecosystem=npm"

# ベンダーアドバイザリ（Fortinet プロダクト）—— ecosystem 指定不要
curl "http://localhost:3001/api/v1/vulnerabilities/search?package=FortiOS&version=7.4.3"
```

**レスポンス例:**
```json
{
  "results": [
    {
      "id": "clxxx...",
      "externalId": "CVE-2019-10744",
      "source": "nvd",
      "severity": "CRITICAL",
      "cvssScore": 9.8,
      "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "summary": "Prototype pollution in lodash",
      "publishedAt": "2019-07-26T00:00:00.000Z",
      "approximateMatch": false,
      "isKev": true,
      "epssScore": 0.97,
      "epssPercentile": 0.998
    }
  ]
}
```

OSV・NVD・ベンダーアドバイザリの3テーブルを並行検索し、**Vulnerability マスターテーブルの ID で重複排除**して返します。同一の CVE が複数ソースに存在する場合も1件のみ返ります（NVD の CVSS データが優先）。

`source` の値:
- `"nvd"` — NVD (CVE ID あり)
- `"osv"` — OSV (CVE ID なし)
- `"advisory"` — ベンダーアドバイザリのみ（CVE ID なし・OSV ID なし）

> `approximateMatch` が `true` の場合、バージョンの正規化に失敗したため、パッケージ名とエコシステムの一致のみで検索された結果です。

> `isKev` が `true` の場合、CISA KEV（Known Exploited Vulnerabilities）カタログに掲載された実際に悪用された脆弱性です。

> `epssScore` は悪用される確率（0〜1）、`epssPercentile` は全CVEの中でのパーセンタイルです。

### 脆弱性検索（バッチ）
複数パッケージを一括で検索します。1リクエストで最大1000件まで対応。
```
POST /api/v1/vulnerabilities/search/batch
```

**リクエスト例:**
```bash
curl -X POST "http://localhost:3001/api/v1/vulnerabilities/search/batch" \
  -H "Content-Type: application/json" \
  -d '{
    "packages": [
      { "package": "lodash", "version": "4.17.20", "ecosystem": "npm" },
      { "package": "requests", "version": "2.31.0", "ecosystem": "PyPI" }
    ]
  }'
```

**レスポンス例:**
```json
{
  "results": [
    {
      "package": "lodash",
      "version": "4.17.20",
      "ecosystem": "npm",
      "vulnerabilities": [
        {
          "id": "clxxx...",
          "externalId": "CVE-2019-10744",
          "source": "nvd",
          "severity": "CRITICAL",
          "cvssScore": 9.8,
          "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "summary": "Prototype pollution in lodash",
          "publishedAt": "2019-07-26T00:00:00.000Z",
          "approximateMatch": false,
          "isKev": true,
          "epssScore": 0.97,
          "epssPercentile": 0.998
        }
      ]
    },
    {
      "package": "requests",
      "version": "2.31.0",
      "ecosystem": "PyPI",
      "vulnerabilities": []
    }
  ]
}
```

### CPE検索（NVD専用）
CPE (Common Platform Enumeration) 文字列で脆弱性を検索します。NVDテーブルのみ対象です。
```
GET /api/v1/vulnerabilities/search/cpe
```

**クエリパラメータ:**
- `cpe` (必須): CPE 2.3 文字列 (例: `cpe:2.3:a:vercel:next.js:15.1.0:*:*:*:*:*:*:*`)
- `limit` (オプション): 結果の最大数 (デフォルト: 500, 最大: 500)
- `offset` (オプション): オフセット (デフォルト: 0)

**リクエスト例:**
```bash
# バージョン指定あり（範囲フィルタが有効）
curl "http://localhost:3001/api/v1/vulnerabilities/search/cpe?cpe=cpe:2.3:a:vercel:next.js:15.1.0:*:*:*:*:*:*:*"

# バージョン省略（vendor+productに一致する全脆弱性）
curl "http://localhost:3001/api/v1/vulnerabilities/search/cpe?cpe=cpe:2.3:a:vercel:next.js:*"
```

CPEの `<version>` 部分が `*` または省略の場合は `approximateMatch: true` で全件返します。

### 脆弱性詳細
CVE ID・OSV ID・アドバイザリ ID（FG-IR-xx-xxx 等）で詳細情報を取得します。
```
GET /api/v1/vulnerabilities/:id
```

**パラメータ:**
- `id`: CVE ID (例: `CVE-2021-44228`)、OSV ID (例: `GHSA-67hx-6x53-jw92`)、またはアドバイザリ ID (例: `FG-IR-25-934`)

**リクエスト例:**
```bash
curl "http://localhost:3001/api/v1/vulnerabilities/CVE-2021-44228"
curl "http://localhost:3001/api/v1/vulnerabilities/GHSA-67hx-6x53-jw92"
curl "http://localhost:3001/api/v1/vulnerabilities/FG-IR-25-934"
```

### 統計情報
データベース内の脆弱性統計を取得します。
```
GET /api/v1/vulnerabilities/stats
```

**レスポンス例:**
```json
{
  "total": 280283,
  "bySeverity": [
    { "severity": "CRITICAL", "_count": 8234 },
    { "severity": "HIGH", "_count": 71234 }
  ],
  "kevCount": 1238,
  "withEpss": 223107,
  "bySource": {
    "osv": 269380,
    "nvd": 11311,
    "advisory": 47,
    "advisoryByVendor": { "fortinet": 47, "paloalto": 21, "cisco": 21 }
  }
}
```

## プロジェクト構造

```
heretix-api/
├── src/
│   ├── api/
│   │   ├── routes/
│   │   │   └── vulnerabilities.ts  # 脆弱性API エンドポイント
│   │   └── server.ts               # Fastifyサーバー設定
│   ├── db/
│   │   └── client.ts               # Prismaクライアント
│   ├── scripts/
│   │   ├── import-osv.ts                    # OSVデータインポートCLI
│   │   ├── import-nvd.ts                    # NVDデータインポートCLI
│   │   ├── import-kev.ts                    # CISA KEVインポートCLI
│   │   ├── import-epss.ts                   # EPSSスコアインポートCLI
│   │   ├── import-fortinet.ts               # Fortinet PSIRTアドバイザリインポートCLI
│   │   ├── import-pan.ts                    # Palo Alto Networks PSIRTアドバイザリインポートCLI
│   │   ├── import-cisco.ts                  # Cisco PSIRTアドバイザリインポートCLI
│   │   ├── import-oracle-linux.ts           # Oracle Linux ELSAインポートCLI
│   │   ├── validate-accuracy.ts             # nginx 検索精度検証（pnpm validate:nginx）
│   │   └── clear-db.ts                      # DB全テーブル削除（Vulnerability含む全テーブル）
│   ├── worker/
│   │   ├── osv-fetcher.ts          # OSV API連携ロジック
│   │   ├── nvd-fetcher.ts          # NVD REST API v2.0連携ロジック
│   │   ├── kev-fetcher.ts          # CISA KEVカタログ取得・インポート
│   │   ├── epss-fetcher.ts         # FIRST.org EPSS日次CSV取得・インポート
│   │   ├── advisory-fetcher.ts     # ベンダーアドバイザリ共通インターフェース・インポート関数
│   │   ├── fortinet-fetcher.ts     # Fortinet PSIRT CSAF取得・パース
│   │   ├── pan-fetcher.ts          # Palo Alto Networks PSIRT CSAF取得・パース
│   │   ├── cisco-fetcher.ts        # Cisco PSIRT openVuln API取得・パース
│   │   └── oracle-linux-fetcher.ts # Oracle Linux OVAL XML取得・bzip2解凍・パース
│   ├── config/
│   │   └── product-aliases.ts      # NVD CPE product 名エイリアスマッピング
│   ├── utils/
│   │   ├── logger.ts               # Pinoロガー設定
│   │   ├── version.ts              # バージョン正規化ユーティリティ
│   │   └── cpe.ts                  # CPE 2.3 パースユーティリティ
│   └── index.ts                    # エントリーポイント
├── prisma/
│   ├── schema.prisma               # データベーススキーマ定義
│   └── migrations/                 # マイグレーションファイル
├── docs/
│   └── erd.md                      # ER図 (Mermaid形式)
├── package.json                    # 依存関係とスクリプト
├── tsconfig.json                   # TypeScript設定
└── .env                            # 環境変数設定
```

### 主要コンポーネント

#### データモデル ([prisma/schema.prisma](prisma/schema.prisma))

```
Vulnerability (マスター)
  ├── cveId      @unique  — CVE ID（NVD/OSV/Advisory 共通の重複排除キー）
  ├── osvId      @unique  — OSV ID（GHSA-xxx, PYSEC-xxx 等、CVE なしの場合のみ）
  ├── advisoryId @unique  — ベンダーアドバイザリ ID（CVE/OSV なしの場合のみ）
  ├── severity / cvssScore / cvssVector / summary
  ├── isKev / kevDateAdded / kevDueDate / ...  — CISA KEV
  ├── epssScore / epssPercentile / epssUpdatedAt — EPSS
  ├── nvdVulnerability       — NVDVulnerability（1対1）
  ├── osvVulnerabilities     — OSVVulnerability[]（1対多）
  └── advisoryVulnerabilities — AdvisoryVulnerability[]（1対多）
```

- **OSVVulnerability** / **OSVAffectedPackage**: OSV・Security Advisory データ（生データ + 検索用フィールド）
- **NVDVulnerability** / **NVDAffectedPackage**: NIST NVD (CVE) データ。CPEをパッケージ名にマッピング
- **AdvisoryVulnerability** / **AdvisoryAffectedProduct**: ベンダーアドバイザリデータ。プロダクト名・バージョン範囲を格納
- **CollectionJob**: データ収集ジョブの状態管理

##### 重複排除キーの優先度

| フィールド | 用途 |
|---|---|
| `cveId` | CVE ID が存在する場合（最優先）。NVD・OSV・アドバイザリが同一行を共有 |
| `osvId` | CVE ID がなく OSV ID がある場合（GHSA-xxx, PYSEC-xxx 等） |
| `advisoryId` | CVE/OSV ID がないベンダーアドバイザリ固有の ID（FG-IR-xx-xxx 等） |

#### バージョン正規化 ([src/utils/version.ts](src/utils/version.ts))
セマンティックバージョニングを整数に変換し、高速な範囲検索を実現:
- `1.2.3` → `1_002_003_000` (major × 1,000,000,000 + minor × 1,000,000 + patch × 1,000 + release)
- RPMリリース番号も4番目のコンポーネントとして含める: `2.9.13-6.el9` → `2_009_013_006`
- PostgreSQLのBigInt型で格納し、インデックスによる高速検索が可能

#### OSVデータ取得 ([src/worker/osv-fetcher.ts](src/worker/osv-fetcher.ts))
- OSV API (`https://api.osv.dev/v1/`) および GCS エコシステムバケットとの連携
- 単一脆弱性の取得、パッケージ別クエリ、バッチインポート、差分更新に対応
- **マルウェア検知**: [ossf/malicious-packages](https://github.com/ossf/malicious-packages) から `MAL-YYYY-NNNN` エントリをインポート。悪意あるパッケージは `/api/v1/vulnerabilities/search` でバージョン完全一致により検索可能
- インポート時に `Vulnerability` マスターテーブルへ自動 upsert
- 差分更新は `CollectionJob` で最終実行日時を管理し、`modified` が更新されていないエントリをスキップ

#### NVDデータ取得 ([src/worker/nvd-fetcher.ts](src/worker/nvd-fetcher.ts))
- NVD REST API v2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`) との連携
- 全件ミラー（ページネーション + CollectionJobで再開可能）
- 差分更新（`lastModStartDate` を使用）
- インポート時に `Vulnerability` マスターテーブルへ自動 upsert（CVSS 権威ソース）

#### KEVデータ取得 ([src/worker/kev-fetcher.ts](src/worker/kev-fetcher.ts))
- CISA KEVカタログ（JSON、約1,200件）を取得
- `Vulnerability.isKev` フラグ・関連フィールドを更新
- full-replace 方式（CISA による削除にも対応）

#### EPSSデータ取得 ([src/worker/epss-fetcher.ts](src/worker/epss-fetcher.ts))
- FIRST.org EPSS API (`https://api.first.org/data/v1/epss`) をページネーション（1万件/ページ）で全件取得（約32万件）
- `Vulnerability.epssScore` / `epssPercentile` を 1000件チャンクで更新

#### ベンダーアドバイザリ基盤 ([src/worker/advisory-fetcher.ts](src/worker/advisory-fetcher.ts))
- `AdvisoryFetcher` インターフェースを実装することで新規ベンダーを追加可能
- `importAdvisoryData()` が `Vulnerability` マスターテーブルへの自動紐付けを担当
- インポート時の優先度: CVE あり → 既存 NVD レコードにリンク / CVE なし → `advisoryId` でマスター管理

#### Fortinet PSIRT取得 ([src/worker/fortinet-fetcher.ts](src/worker/fortinet-fetcher.ts))
- RSS フィード (`https://filestore.fortinet.com/fortiguard/rss/ir.xml`) から最新アドバイザリ一覧を取得
- CSAF 2.0 JSON (`https://filestore.fortinet.com/fortiguard/psirt/csaf_*.json`) で構造化データを取得
- バージョンブランチごとに個別レコードを作成（例: FortiOS 7.6.x / 7.4.x / 7.2.x を分離）
- `lastAffectedInt` による inclusive 範囲境界の正確な検索
- 認証不要・レート制限なし（公開フィード）

#### Palo Alto Networks PSIRT取得 ([src/worker/pan-fetcher.ts](src/worker/pan-fetcher.ts))
- RSS フィード (`https://security.paloaltonetworks.com/rss.xml`) からアドバイザリ一覧を取得
- CSAF JSON (`https://security.paloaltonetworks.com/csaf/{ID}`) を個別取得・パース
- `vers:generic/<VERSION` 形式のバージョン範囲を解析して `versionEnd` / `versionFixed` に変換
- 認証不要・レート制限なし（公開フィード）

#### Cisco PSIRT取得 ([src/worker/cisco-fetcher.ts](src/worker/cisco-fetcher.ts))
- OAuth 2.0 (`CISCO_CLIENT_ID` / `CISCO_CLIENT_SECRET`) でアクセストークンを取得
- openVuln API (`https://apix.cisco.com/security/advisories/v2/advisories/all`) でアドバイザリ一覧を取得
- 各アドバイザリの `csafUrl` から CSAF JSON を取得して製品・バージョン情報を補完
- `pnpm import:cisco latest` で最新100件のみ取得する増分モードをサポート

#### Oracle Linux ELSA取得 ([src/worker/oracle-linux-fetcher.ts](src/worker/oracle-linux-fetcher.ts))
- Oracle 公式 OVAL XML フィード（bzip2 圧縮、認証不要）をダウンロード
- ELSA アドバイザリの深刻度・CVE リスト（CVSS スコア付き）・影響パッケージを解析
- `criterion` のコメント文（"X is earlier than Y"）から `versionEnd`（exclusive）を抽出
- `ol9` / `ol8` / `ol7` 等のバリアント別フィードに対応
- RPM リリース番号（例: `2.9.13-6.el9`）は `normalizeVersion()` で4番目のコンポーネントとして正規化

## NVDデータ収集

### 初回フルダウンロード（全件ミラー）
```bash
pnpm import:nvd full
```
約24万件のCVEを全件取得します。途中で失敗した場合は `CollectionJob` に進捗が保存されており、ジョブIDを指定して再開できます。

```bash
pnpm import:nvd full <job-id>
```

| 条件 | 所要時間の目安 |
|---|---|
| NVD_API_KEY なし (10 req/min) | 約12分 |
| NVD_API_KEY あり (50 req/min) | 約2.5分 |

### 差分更新
```bash
pnpm import:nvd update
```

### 単一CVEの取得
```bash
pnpm import:nvd cve CVE-2021-44228
```

### 日付範囲指定
```bash
pnpm import:nvd range 2024-01-01 2024-03-31
```

NVD API の 120 日制限を自動的に 120 日以内のチャンクに分割して取得します。2 年分など長期間の指定も可能です。

### NVD APIキー（推奨）

`.env` に設定することでレート制限が緩和されます:
```env
NVD_API_KEY=your-api-key-here
```
APIキーは [NVD公式サイト](https://nvd.nist.gov/developers/request-an-api-key) で無料取得できます。

## OSVデータ収集

### サンプルデータのインポート
```bash
pnpm import:osv sample
```

### 特定パッケージの脆弱性をインポート
```bash
pnpm import:osv package npm lodash
pnpm import:osv package PyPI requests
```

### エコシステム全体のインポート（全件）
```bash
pnpm import:osv ecosystem npm
pnpm import:osv ecosystem PyPI
pnpm import:osv ecosystem Go         # Go モジュール
pnpm import:osv ecosystem Packagist  # PHP Composer パッケージ
```

**`ecosystem` / `update` コマンドで指定できるエコシステム一覧:**

| 指定値 | 言語・プラットフォーム |
|---|---|
| `npm` | Node.js |
| `PyPI` | Python |
| `Go` | Go モジュール |
| `RubyGems` | Ruby |
| `crates.io` | Rust |
| `Packagist` | PHP (Composer) |
| `Maven` | Java / Kotlin |
| `NuGet` | .NET |
| `Hex` | Elixir / Erlang |
| `Pub` | Dart / Flutter |
| `ConanCenter` | C / C++ |
| `SwiftURL` | Swift |
| `CRAN` | R |
| `Linux` | Linux カーネル |
| `Android` | Android |
| `OSS-Fuzz` | OSS-Fuzz プロジェクト |
| `Bitnami` | Bitnami アプリケーションスタック |

> エコシステム名は**大文字小文字を区別します**。上記の表記を正確に使用してください。
> Linux ディストリビューション系（Alpine、Debian、Ubuntu、AlmaLinux、Rocky Linux 等）はバージョンなしでインポートできます（例: `pnpm import:osv ecosystem Ubuntu`）。**検索時**はバージョン省略可能で、`?ecosystem=Ubuntu` と指定すると全 Ubuntu バージョンにプレフィックスマッチします。`?ecosystem=Ubuntu:22.04:LTS` とすれば特定バージョンに絞り込めます。なお、これらのエコシステムはディストリビューション形式のバージョン文字列を格納するため、アップストリームの semver バージョンは一致しません。

### 差分更新（前回実行以降の変更分のみ）
```bash
pnpm import:osv update npm           # npm の差分更新
pnpm import:osv update PyPI          # PyPI の差分更新
pnpm import:osv update malware       # MAL エントリの差分更新
```

差分更新は全件 ZIP をダウンロードしますが、`modified` タイムスタンプが前回の `CollectionJob` 完了時刻以前のエントリをスキップします。初回実行時は過去30日分を対象にします。

### マルウェア検知（MAL エントリ）

[ossf/malicious-packages](https://github.com/ossf/malicious-packages) の悪意あるパッケージ情報をインポートします。

```bash
pnpm import:osv malware              # 全件インポート（初回）
pnpm import:osv update malware       # 差分更新（2回目以降）
```

インポート後は通常の脆弱性検索で MAL エントリが取得できます：
```bash
curl -H "x-api-key: $API_KEY" \
  "http://localhost:5000/api/v1/vulnerabilities/search?package=event-stream&version=3.3.6&ecosystem=npm"
```

> `update malware` はファイル一覧取得のために GitHub API を **1回だけ**呼び出します（未認証: 60 req/時）。スケジューラは1日1回の実行のため、通常 `GITHUB_TOKEN` は不要です。

### 特定IDでインポート
```bash
pnpm import:osv id GHSA-67hx-6x53-jw92
pnpm import:osv id CVE-2021-44228
```

## CISA KEVデータ収集

CISA（米国サイバーセキュリティ・インフラセキュリティ庁）が公開する悪用実績のある脆弱性カタログです。

```bash
pnpm import:kev full    # カタログを取得してマスターテーブルに反映
pnpm import:kev stats   # DB の KEV 統計を表示
```

- 約1,200件の CVE が対象
- `Vulnerability.isKev = true` でフラグ付け
- CISA が CVE を削除した場合にも対応（full-replace 方式）
- カタログは [CISA公式サイト](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) で公開

## EPSSスコア収集

FIRST.org が提供する、脆弱性が今後30日以内に悪用される確率のスコアです。

```bash
pnpm import:epss full              # 本日の日次CSVを全件取得して反映
pnpm import:epss full 2024-03-01   # 指定日付のCSVを取得
pnpm import:epss cve CVE-2021-44228  # 単一CVEのみ更新
```

- 約32万件の CVE にスコアが付与されている
- 毎日更新（日次実行を推奨）
- `epssScore`: 0〜1 の悪用確率、`epssPercentile`: 全CVEの中でのパーセンタイル

## ベンダーセキュリティアドバイザリ収集

### Fortinet PSIRT

Fortinet の公式 PSIRT（製品セキュリティインシデント対応チーム）アドバイザリを収集します。

```bash
pnpm import:fortinet
```

- RSS フィード（最新約50件）+ CSAF 2.0 JSON で取得（認証不要）
- FortiOS・FortiProxy・FortiManager・FortiAnalyzer 等 Fortinet 製品全般を対象
- バージョンブランチ（7.6.x / 7.4.x / 7.2.x 等）ごとに個別レコードを作成
- CVE ID があれば NVD の `Vulnerability` レコードと自動リンク（KEV/EPSS も活用可能）

#### 検索例

```bash
# FortiOS 7.4.3 に影響する脆弱性を検索（ecosystem 不要）
curl "http://localhost:3001/api/v1/vulnerabilities/search?package=FortiOS&version=7.4.3"

# アドバイザリ ID で詳細を取得
curl "http://localhost:3001/api/v1/vulnerabilities/FG-IR-25-934"
```

### Palo Alto Networks PSIRT

Palo Alto Networks の PSIRT アドバイザリを収集します。

```bash
pnpm import:pan
```

- RSS フィード + CSAF JSON で取得（認証不要）
- PAN-OS・Prisma Access・Cortex XDR 等 PAN 製品全般を対象
- `vers:generic/` 形式のバージョン範囲を解析して `versionEnd`（exclusive）と `versionFixed` に変換

#### 検索例

```bash
# PAN-OS Firewall に影響する脆弱性を検索
curl "http://localhost:3001/api/v1/vulnerabilities/search?package=PAN-OS+Firewall&version=12.1.3"
```

### Cisco PSIRT

Cisco の PSIRT アドバイザリを収集します。`CISCO_CLIENT_ID` と `CISCO_CLIENT_SECRET` が必要です。

```bash
pnpm import:cisco          # 全件取得（初回）
pnpm import:cisco latest   # 最新100件のみ（差分更新）
```

- OAuth 2.0 認証（openVuln API）+ CSAF JSON で取得
- Cisco IOS XE・NX-OS・ASA・FTD 等 Cisco 製品全般を対象
- 必須環境変数: `CISCO_CLIENT_ID`・`CISCO_CLIENT_SECRET`（[Cisco Developer Portal](https://apiconsole.cisco.com/) で取得）

#### 検索例

```bash
# Cisco IOS XE に影響する脆弱性を検索
curl "http://localhost:3001/api/v1/vulnerabilities/search?package=ios_xe&version=17.6.1"
```

### Oracle Linux ELSA

Oracle Linux のセキュリティアドバイザリ（ELSA）を収集します。認証不要。

```bash
pnpm import:oracle-linux              # 全バージョン（all.xml.bz2）
pnpm import:oracle-linux ol9          # Oracle Linux 9 のみ
pnpm import:oracle-linux ol8          # Oracle Linux 8 のみ
```

- Oracle 公式 OVAL XML フィード（bzip2 圧縮）を利用（認証不要）
- ELSA ID・深刻度・CVE・影響パッケージ/バージョン範囲を取得
- RPM バージョン（例: `2.9.13-6.el9`）で範囲検索が可能

#### 検索例

```bash
# Oracle Linux の rsync パッケージに影響する脆弱性を検索
curl -H "x-api-key: $API_KEY" \
  "http://localhost:5000/api/v1/vulnerabilities/search?package=rsync&ecosystem=oracle-linux&version=3.2.4"
```

> **ecosystem の値**: `oracle-linux`（バージョンサフィックスなし）。バージョンは RPM 形式（`3.2.5-3.el9`）または upstream 形式（`3.2.4`）を指定できます。

### 新規ベンダーの追加方法

`AdvisoryFetcher` インターフェースを実装するだけで新規ベンダーを追加できます:

```typescript
// src/worker/my-vendor-fetcher.ts
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';

export class MyVendorFetcher implements AdvisoryFetcher {
  source() { return 'myvendor'; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    // ベンダーAPIを叩いて NormalizedAdvisory[] に変換して返す
  }
}
```

その後 `runAdvisoryFetcher(new MyVendorFetcher())` を呼び出すだけで、マスターテーブルへの紐付けを含む全インポート処理が自動的に行われます。

## アーキテクチャの特徴

### マスターテーブルによる重複排除

複数ソースに同一の CVE が存在する場合でも、`Vulnerability` マスターテーブルが CVE ID をキーに1件に統合します。

```
CVE-2021-44228 (Log4Shell)
  ├── NVDVulnerability            ─┐
  ├── OSVVulnerability (GHSA-...) ─┤→ Vulnerability (cveId: "CVE-2021-44228", isKev: true)
  └── AdvisoryVulnerability       ─┘   ↑ 全ソースが同一マスター行を共有
```

CVE ID を持たないアドバイザリは `advisoryId` フィールドで独立したマスター行として管理されます。

### 高速バージョン検索の仕組み

1. **バージョンの整数化**: `1.2.3` → `1_002_003_000`（PostgreSQL BigInt）; RPM `2.9.13-6.el9` → `2_009_013_006`
2. **インデックス検索**: `(ecosystem, packageName)` + `(packageName, introducedInt, fixedInt)`

```sql
WHERE ecosystem = 'npm'
  AND packageName = 'lodash'
  AND introducedInt <= 4017020000
  AND (fixedInt IS NULL OR fixedInt > 4017020000)
```

ベンダーアドバイザリでは `versionStartInt` / `lastAffectedInt`（inclusive）または `versionEndInt`（exclusive）による範囲検索、加えて `affectedVersions` 配列への完全一致検索も並行実施します。

### ソース優先度

| フィールド | 優先ソース |
|---|---|
| cvssScore / cvssVector / severity | NVD（権威ソース、常に上書き） |
| summary / publishedAt | NVD 優先、null の場合のみ OSV/Advisory で補完 |
| isKev / kev* | CISA KEV（独立更新） |
| epssScore / epssPercentile | FIRST.org EPSS（独立更新） |
| workaround / solution / url | Advisory（ベンダー固有情報） |

## 自動スケジューラ

サーバー起動時に `src/scheduler.ts` が以下の定期ジョブを登録します:

| ジョブ | スケジュール |
|---|---|
| NVD 差分更新 | 2 時間ごと |
| KEV 全件置き換え | 毎日 09:00 UTC |
| EPSS 一括更新 | 毎日 10:00 UTC |
| Fortinet アドバイザリ | 毎日 11:00 UTC |
| PAN アドバイザリ | 毎日 11:15 UTC |
| Cisco アドバイザリ | 毎日 11:30 UTC |
| OSV 差分更新（DB 内エコシステム全て） | 毎日 08:00 UTC |
| MAL 差分更新（ossf/malicious-packages） | 毎日 08:30 UTC |

OSV はエコシステムごとに独立したジョブ（`osv-{ecosystem}`）として実行されるため、ダッシュボードでエコシステム単位のステータスを確認できます。

## 開発・デプロイガイド

### Docker（推奨）

```bash
# 環境変数ファイルを作成・編集
cp .env.example .env

# フォアグラウンドで起動（初回はログを確認しながら起動することを推奨）
API_KEY=your-api-key docker compose up --build

# バックグラウンドで起動（デタッチモード）
API_KEY=your-api-key docker compose up --build -d
```

API は `http://localhost:5000` で起動します。

停止は `docker compose down`。`-v` を追加するとデータベースボリュームも削除されます。

### 手動

#### ビルド
```bash
pnpm build
```

#### 本番環境での起動
```bash
pnpm start
```

### 環境変数
```env
DATABASE_URL="postgresql://user:password@host:5432/dbname?schema=public"
PORT=3001
NODE_ENV=production
API_KEY=your-api-key-here   # Required. Requests without x-api-key header return 401
NVD_API_KEY=                # Optional. Relaxes NVD rate limit from 10 → 50 req/min
CISCO_CLIENT_ID=            # Required for Cisco PSIRT import (openVuln API client ID)
CISCO_CLIENT_SECRET=        # Required for Cisco PSIRT import (openVuln API client secret)
GITHUB_TOKEN=               # Optional. MAL インポート時の GitHub tree API 呼び出し（1回のみ）を認証する。同一 IP から1時間に60回以上実行する場合のみ必要。
```

### CPEマッピングについて

NVDはCPE (Common Platform Enumeration) 形式で影響製品を記述します。本APIでは `cpe:2.3:a:` (application) および `cpe:2.3:o:` (OS) の `<product>` 部分をパッケージ名として使用し、`<vendor>` からエコシステムを推定します（ベストエフォート）。`cpe:2.3:h:` (hardware) はバージョンが常に `-` のため対象外です。

CPE にはバージョン範囲フィールド（`versionStartIncluding` 等）と、URI 自体にバージョンが直接埋め込まれる2種類があります。後者（例: `cpe:2.3:a:vendor:product:3.0:*:*:*:*:*:*:*`）は「特定バージョンのみ影響あり」として `introduced = lastAffected = 3.0` に変換します。

| vendor | 推定 ecosystem |
|---|---|
| `python` / `pypi` | `PyPI` |
| `nodejs` / `npm` | `npm` |
| `redhat` / `almalinux` | `AlmaLinux` |
| `golang` | `Go` |
| `rubygems` | `RubyGems` |

## 既知の問題・制限事項

### Ubuntu/Debian OSV アドバイザリの偽陽性（対処済み）

**背景**: Ubuntu/Debian 系の OSV アドバイザリは `introduced: "0"` + `fixed: "<ubuntu_patched_version>"` を「このパッケージの更新が必要」という意味で使用する。これは upstream の脆弱性バージョン範囲ではなく配布パッケージの更新要否を示すものであるため、upstream バージョンで semver range 比較すると偽陽性が発生する。

**現在の動作**:
- **ecosystem 未指定**: `Ubuntu:*` / `Debian:*` / `Alpine:*` / `AlmaLinux:*` / `Rocky:*` / `Red Hat:*` / `CentOS:*` 等のディストリビューション固有エコシステムを検索対象から除外
- **ecosystem 明示指定**（例: `ecosystem=Ubuntu:20.04:LTS`）: dpkg/rpm 形式のパッケージバージョンによる `affectedVersions` exact match を使用。upstream バージョンは distro 形式と一致しないため偽陽性が発生しない
- **エコシステムエイリアス**: `composer` は自動的に `Packagist`（PHP Composer パッケージの OSV エコシステム名）に変換される

**エコシステム別の検索ロジック**:

| ecosystem の種類 | 検索方式 |
|---|---|
| `Ubuntu:*` / `Debian:*` / `Alpine:*` / `AlmaLinux:*` / `Rocky:*` / `Red Hat:*` / `CentOS:*` | `affectedVersions` exact match（dpkg/apk/rpm 形式バージョン） |
| `npm` / `PyPI` / `Go` / `Maven` 等 upstream | semver range 比較（従来通り） |
| 未指定 | upstream のみ（ディストリビューション固有を除外） |

**使い方**: ディストリビューション固有エコシステムで検索する場合は、OS のパッケージバージョン形式（`apt show xz-utils` 等で確認できる値）を指定してください。

```
# 正しい例（Ubuntu 20.04 のパッケージバージョンで検索）
GET /api/v1/vulnerabilities/search?package=xz-utils&version=5.2.4-1ubuntu1&ecosystem=Ubuntu:20.04:LTS

# upstream バージョンでは distro ecosystem にヒットしない（意図通り）
GET /api/v1/vulnerabilities/search?package=xz-utils&version=5.1.1&ecosystem=Ubuntu:20.04:LTS
→ {"results": []}
```

### NVD と OSV のパッケージ名の表記ゆれ

NVD は CPE の `product` フィールドをパッケージ名として使用するため、OSV のパッケージ名と一致しない場合がある（例: NVD=`xz`、OSV=`xz-utils`）。両方のデータを同時に検索するには名寄せが必要。（未実装）

### 検索の limit/offset がメモリ上での処理に依存している

現在の検索実装では `NVDAffectedPackage` / `OSVAffectedPackage` を limit なしで全件取得し、メモリ上で dedup した後に `limit/offset` を適用している。これは curl（約 900 件）程度では問題ないが、`openssl` や `linux_kernel` のように CPE エントリが数千件に及ぶパッケージでは応答時間・メモリ使用量が増加する可能性がある。

改善策として、`Vulnerability` テーブルをベースにして `AffectedPackage` を JOIN 条件として使うクエリ構造に変更することで、DB 側で正確な件数ページネーションが可能になる。（未実装）

---

## トラブルシューティング

### データベース接続エラー
```
Error: P1001: Can't reach database server
```
- `.env`ファイルの`DATABASE_URL`を確認
- PostgreSQLサーバーが起動しているか確認
- ファイアウォール/セキュリティグループの設定を確認

### マイグレーションエラー
```bash
# マイグレーション状態をリセット
pnpm prisma migrate reset

# 再度マイグレーション実行
pnpm db:migrate
```

### バージョン正規化の注意点

バージョン文字列は `major × 1,000,000,000 + minor × 1,000,000 + patch × 1,000 + release` の整数に変換されます。

| 項目 | 動作 | 影響 |
|---|---|---|
| プレリリース版 (`1.0.0-beta.1`) | 正式版より小さい値として扱う (`1.0.0` - 1) | 軽微な誤差の可能性 |
| ビルドメタデータ (`1.0.0+build.123`) | 除去して無視 | 影響なし |
| RPM リリース番号 (`2.9.13-6.el9`) | リリース番号 (6) を4番目のコンポーネントとして含める → `2_009_013_006` | サブリリース単位の範囲検索が可能 |
| 各コンポーネントが 999,999 超 | 正規化失敗 (null) | フォールバック検索に移行 |
| 非 semver 形式 (日付ベース等) | 正規化失敗 (null) | フォールバック検索に移行 |

**フォールバック検索**: バージョンの正規化に失敗した場合、パッケージ名とエコシステムの一致で関連する全脆弱性を返します。この場合、レスポンスの各脆弱性レコードに `approximateMatch: true` が付与されます。

## ライセンス

Apache License 2.0 — 詳細は [LICENSE](LICENSE) を参照してください。

## 貢献

Issue、Pull Requestを歓迎します。
