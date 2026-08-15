# 精度検証

[English version](ACCURACY.md)

公式セキュリティアドバイザリを正解データとして Precision / Recall を計測するスクリプト。対象製品は今後も増えていく想定。それ以外の内容は [README.ja.md](README.ja.md) を参照。

```bash
pnpm validate:tomcat 9.0.100      # vs tomcat.apache.org
pnpm validate:apache 2.4.62       # vs httpd.apache.org
pnpm validate:nginx 1.24.0        # vs nginx.org
pnpm validate:openssl 3.0.12      # vs openssl.org
pnpm validate:postgresql 16.4     # vs postgresql.org
```

## 境界値スイープ（nginx / tomcat / apache）

専用の `AdvisoryFetcher`（`advisory-nginx`、`advisory-tomcat`、`advisory-apache`）を持つ製品では、同じコマンドを**バージョン引数なしで**実行するとスイープモードに切り替わる。公式ページから全アドバイザリの範囲境界（`introduced`、`lastAffected`/`fixed`、およびそれぞれの1パッチ先）を自動的に導出し、その全ての境界バージョンで検索エンドポイントに問い合わせて Precision/Recall/F1 を集計する。単発の手動選定バージョンではまず引っかからない off-by-one バグを検出できるのはこの方式だからこそ。

結果は raw なマルチソースのエンドポイント全体ではなく、その製品自身の fetcher を含む `sources`（例: `advisory-nginx`）に絞り込んでいる。理由は下の[既知の制限事項](#既知の制限事項)を参照。

```bash
pnpm validate:nginx     # スイープモード（バージョン引数なし）
pnpm validate:tomcat
pnpm validate:apache
```

| 製品 | テストした境界バージョン数 | TP | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| nginx | 91 | 1,873 | 100.00% | 100.00% | 100.00% |
| Apache Tomcat | 336 | 12,374 | 100.00% | 100.00% | 100.00% |
| Apache HTTP Server | 56 | 4,112 | 100.00% | 100.00% | 100.00% |

*2026-07-21 に再現確認。483件の境界ケース全てで、各 fetcher 自身のデータに対する偽陽性・偽陰性はゼロだった。*

## 境界値スイープ（Fortinet / Palo Alto Networks）

FortinetとPANのアドバイザリは、影響製品エントリごとに2種類の範囲表現が混在する: 厳密なバージョン一覧、または範囲（`versionStart`/`versionEnd`/`versionFixed`/`lastAffected`）。両fetcherとも、同一エントリに包括的な`lastAffected`と補助的な`versionFixed`を同時に設定することがある——`importAdvisoryData()`はこれを「`versionEnd ?? versionFixed`（排他的）を優先し、どちらも無い場合のみ`lastAffected`（包括的）にフォールバックする」という優先順位で解決している。ground truth（`src/scripts/lib/accuracy-sweep.ts`の`indexGenericByProduct`/`expectedIdsGeneric`）はこの優先順位を正確に再現しており、両方を独立にチェックする方式ではない——それをやると検索エンドポイントの実際の挙動と静かに食い違ってしまう。

```bash
pnpm validate:fortinet   # スイープモード: 全Fortinet製品
pnpm validate:pan        # スイープモード: 全PAN製品（本番ジョブと同じ mode: 'all'）
```

| 製品 | テストした境界バージョン数 | TP | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| Fortinet | 1,019 | 14,612 | 100.00% | 100.00% | 100.00% |
| Palo Alto Networks | 235 | 5,881 | 99.56% | 99.98% | 99.77% |

*2026-07-26 に再現確認。この作業中に3件の実バグが見つかった——検証ハーネス側2件、本番側1件。

1. **ハーネス側バグ**: `expectedIdsGeneric`に実際のロジックの穴があった——完全一致リストのみ（範囲データを一切持たない）のエントリが、指定バージョンにマッチしなかった場合、後続の全チェックを素通りして（比較対象が何も無いため）無条件マッチにたどり着いてしまい、結果として*他のあらゆるバージョンにも誤ってマッチしていた*。`accuracy-sweep.ts`で修正済み。
2. **本番側のギャップ**: `FortinetFetcher`はRSSのみでアドバイザリを発見していたが、これは「新着」フィードであり直近約50件のローリングウィンドウしか見えない——全件アーカイブではない（PANの`mode: 'all'`は既にPANの全アドバイザリ一覧をページネーションしている）。過去のスケジュール実行でDBに既に入っていた古いアドバイザリが、一度きりのground truth取得では見えないという理由だけで誤検知としてフラグされていた。本当の修正は`FortinetFetcher`自体に`mode: 'all'`を追加すること（PANの前例に合わせてデフォルトに設定）——PSIRTアドバイザリ一覧ページ（`fortiguard.fortinet.com/psirt?page=N`、21ページ・2018年まで遡る約300件）を全ページスクレイピングし、RSSに依存しないようにした。これは検証スクリプト側の回避策ではなく、本番の実データ網羅性そのものの改善。
3. PANの唯一残る不一致（CVE-2025-9132）は実在の許容済み制約: Chromiumスタイルの4コンポーネントバージョン（Prisma Browser、例: `138.53.6.158`）が`normalizeVersion()`で3コンポーネントに切り詰められてしまう——既に文書化済みのRPMサブリリース問題（`el9` vs `el9_7.2`）と同種の精度低下であり、同じ理由でここでも修正していない（git履歴参照）。

上記のFortinetの数字は、修正後の`mode: 'all'`フェッチャー（254件、RSSのみの場合の約47件から増加）によるもの。*

## 境界値スイープ（RHEL / Oracle Linux）

RHEL・Oracle Linux のアドバイザリは常に排他的な上限（「`<パッケージ>` は `<バージョン>` より前」）のみを表現し下限を持たないため、「introduced」の境界は存在せず、「fixed exact（影響なしを期待）」と「fixed の1つ前のRPMリリース（影響ありを期待）」のみをテストする。ground truth は本番の `RedHatFetcher`/`OracleLinuxFetcher` 自身をその場でライブフィードから取得したものを使う（同じページを独立に再パースする専用スクリプトは書かない — `validate:apache` の開発中に実際に踏んだ「2つの独立したパーサーが乖離する」問題を繰り返さないため）。結果はnginx/tomcat/apacheと同様、fetcher自身の `sources` に絞り込んでいる。

```bash
pnpm validate:redhat          # スイープモード: RHEL 8+9 の全パッケージ
pnpm validate:oracle-linux    # スイープモード: Oracle Linux の全パッケージ（1製品あたり境界点を50件に制限——kernel-uek系など1製品で19,000件超のfixedバージョンを持つパッケージがあり、サンプリングしないと数時間かかるため）
```

| 製品 | テストした境界ポイント数 | TP | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| Red Hat (RHEL 8+9) | 105,049 | 40,622,977 | 99.97% | 99.98% | 99.98% |
| Oracle Linux | 97,538 | 7,822,599 | 99.48% | 100.00% | 99.74% |

*2026-07-25/26 に再現確認。残存するわずかなFP/FNはコードのバグではない——上位の該当CVEを個別に確認したところ、DBが最後にインポートされてから ground truth を取得するまでの数時間の間に、ベンダー側のライブOVALフィード自体が改訂されていた（例: あるアドバイザリの影響パッケージ一覧に追加/削除があった）ことが分かった。ライブの上流フィードと定期インポートされたスナップショットを比較する以上避けられないズレであり、検索やfetcherの欠陥ではない。Recallがほぼ完全（99.98%/100%）なのは、このスイープの初期版が `kernel` 等の大量パッチ済みパッケージ（500件超のCVEを返す）に対してページネーションをせずAPIの500件上限に引っかかっていたのを、validateスクリプト側で全ページ取得するよう修正した結果。*

## 境界値スイープ（Node.jsモジュールストリーム / RHEL & Oracle Linux）

ここでのground truthは意図的に`RedHatFetcher`/`OracleLinuxFetcher`自身のパース済みデータを**使わない**——fetcherが読んでいるのと同じフィードから構築した「ground truth」は本番と全く同じ死角を共有してしまい、あるDNFモジュールストリーム（例: `nodejs:22`）の修正が別の無関係なストリーム（例: `nodejs:10`）へのクエリに漏れ込むケースを原理的に検出できない。代わりに、独立した[nodejs/security-wgの脆弱性インデックス](https://github.com/nodejs/security-wg/blob/main/vuln/core/index.json)をground truthとして使う——`vulnerable`/`patched`フィールドがメジャー系統ごとのsemver範囲を表現しており、RHEL/Oracle Linuxが実際にパッケージ化しているモジュールストリームのメジャーバージョン（10/12/14/16/18/20/22/24）に絞り込んでいる。修正と残存する問題の背景は[README.jaの既知の問題](README.ja.md#rheloracle-linuxのモジュールストリームによる偽陽性根本原因を修正済みnodejspostgresql以外は一部残存)を参照。

```bash
pnpm validate:nodejs                        # スイープモード, vendor=red-hat
pnpm validate:nodejs --vendor=oracle-linux  # スイープモード, vendor=oracle-linux
```

| ベンダー | 段階 | 境界ポイント数 | TP | FP | FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Red Hat (RHEL 8+9) | 修正前 | 154 | 2,507 | 13,199 | 802 | 15.96% | 75.76% | 26.37% |
| Red Hat (RHEL 8+9) | + Module criterionからのversionStart | 154 | 2,309 | 4,265 | 1,000 | 35.12% | 69.78% | 46.73% |
| Red Hat (RHEL 8+9) | + bare行フォールバック | 154 | 2,257 | 2,157 | 1,052 | **51.13%** | 68.21% | **58.45%** |
| Oracle Linux | 修正前 | 154 | 2,459 | 13,015 | 850 | 15.89% | 74.31% | 26.18% |
| Oracle Linux | + Module criterionからのversionStart | 154 | 2,112 | 8,346 | 1,197 | 20.20% | 63.83% | 30.68% |
| Oracle Linux | + bare行フォールバック | 153 | 2,042 | 2,059 | 1,267 | **49.79%** | 61.71% | **55.11%** |

*2026-08-11に再現確認。修正した順に:*

1. *ベースライン: 両fetcherとも`"<package> is earlier than <version>"`criterionだけをパースし、同じOVAL AND-block内の兄弟criterionである`"Module <名前>:N is enabled"`を読み捨てていた。モジュール行には`versionStart`が一切無いため、古い系統へのクエリが新しい系統の修正に数値的に一致してしまう。*
2. *このModule criterionからインポート時点で直接`versionStart`を抽出する（両fetcherの`collectCriteria()`）ことで、Precisionはおおよそ倍になった。適用前に自己限定性を検証済み: RHEL9の実フィード中のnodejs関連`<definition>`全件で「Module criterionの有無」と「`versionEnd`に`.module+`を含むか」が完全一致（不一致0件）——つまりモジュール化されていない約9,364製品名には原理上触れられない。nodejsに限らず全DNFモジュール製品に適用した。*
3. *残ったFPは、パッケージがモジュール化される前のアドバイザリでModule criterion自体が存在しないケース（例: RHEL9の`RHSA-2022:6595`、`nodejs 16.16.0-1.el9_0`）が原因だった。`inferBareVersionStart()`（`src/worker/advisory-helpers.ts`）がその行自身の`versionEnd`にフォールバックする——ただし`nodejs`・`postgresql`・`httpd`（いずれも下記参照）に厳密に絞った。modular行とbare行が混在する(製品, ベンダー)組み合わせが他に917件見つかっており、それらで同じ前提が成り立つかは未検証のため。*

*Recallは62〜70%程度で下げ止まり、上記の修正では大きく変化しなかった（過剰検知を除去するだけで検知漏れは埋めないため想定通り）。見逃した79件のユニークCVEをDBと突き合わせたところ、39件（49%）はどのメジャーでも`red-hat`/`oracle-linux`の`nodejs`行が一切存在しなかった。データの欠落ではなく、ground truth（upstreamの`nodejs/security-wg`）がディストロの実際の配布期間という概念を持たないことが原因: RHEL8の`nodejs:10`系統の最初のビルドは`10.14.1`で、CVE-2018-7161等（upstream修正`10.4.1`）はそもそも脆弱なビルドを配布したことが無く直す対象が無かった。逆にCVE-2021-3449（upstream修正`10.24.1`）は`nodejs:10`系統の最終ビルド`10.24.0`より後で、upstream Node.js 10自体の2021年4月EOLとほぼ同時にモジュールも終了しバックポートされなかった。検索やfetcherの欠陥ではなく`validate-nodejs.ts`のground truthモデルの限界——直すなら各系統の実配布範囲をDBの`versionEnd`から検証スクリプトに教える改修が必要（本番ロジックは無関係）。まだ未実装。*

## サンプリングによる実測（Ubuntu / Debian / Alpine）

上記のベンダーOVAL/HTMLソースと違い、OSVデータは既に構造化されたJSONとして届くため、自前のスクレイピング・パース工程が存在しない——インポート済みの`OSVAffectedPackage`行そのものが既にground truthなので、これらのスクリプトはライブで再取得せず、DBを直接読む。これらのエコシステムは数百万行規模（Ubuntuだけで約190万行）——全数スイープが現実的な桁を大きく超えているため、網羅的ではなく**サンプリング**による検証とした: 明示的な`affectedVersions`一覧を持つ行を500件（既存の完全一致経路を検証）、一覧を持たず範囲情報のみの行を500件（下記のdpkg範囲フォールバックを検証）。

スイープスクリプトを書く前の「ground truthとは何か」を検討する段階で、実際に本番バグを1件発見した。Debianの大半のOSVエントリ（および一部のUbuntu/Alpine）は`introduced`/`fixed`の連続範囲のみを公開し、明示的な`versions`一覧を一切持たない。ディストロエコシステムの検索は`affectedVersions`との完全一致方式のみを使っていたため、**Debianの OSV データの約68%で、バージョン指定検索がどんなバージョンを指定しても常に空振りしていた**。`compareDpkgVersions()`（[`src/utils/dpkg-version.ts`](src/utils/dpkg-version.ts)、dpkgのバージョン比較アルゴリズム）を範囲比較のフォールバックとして実装して修正した——完全一致を先に試し、一覧にバージョンが含まれない（または一覧自体が存在しない）場合のみ範囲比較にフォールバックする。詳細は [`README.ja.md`の既知の問題・制限事項](README.ja.md#既知の問題制限事項) を参照。

```bash
pnpm validate:debian
pnpm validate:ubuntu
pnpm validate:alpine
```

| エコシステム | テストしたポイント数 | TP | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| Debian | 1,500 | 999 | 100.00% | 99.90% | 99.95% |
| Ubuntu | 1,500 | 1,000 | 100.00% | 100.00% | 100.00% |
| Alpine | 1,039 | 539 | 100.00% | 100.00% | 100.00% |

*2026-07-26（修正後）に再現確認。Debianの唯一の見逃しは Bazaar リビジョン形式のバージョン文字列（`0~bzrNNN`）に関するもので、自動生成した「fixed-1」境界ポイントが実際のdpkg順序でちょうど1つ手前の値になっていない——珍しいバージョン体系向けに境界点を自動導出する際の癖であり、実際のアドバイザリデータに対する検索の見逃しの再現ではない。*

## 単一バージョンでの実測（openssl / PostgreSQL）

OpenSSL と PostgreSQL には専用の `AdvisoryFetcher` が無い（NVD/OSV のみでカバー）ため、`pnpm validate:openssl`/`pnpm validate:postgresql` は常に明示的なバージョン指定が必要（スイープモードなし。理由は下の[既知の制限事項](#既知の制限事項)を参照）。

```bash
pnpm validate:openssl 3.5.0
pnpm validate:postgresql 16.4
```

| 製品 | バージョン | TP | FP | FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|
| OpenSSL | 3.5.0 | 36 | 0 | 2 | 100.00% | 94.74% | 97.30% |
| PostgreSQL | 16.4 | 20 | 1 | 4 | 95.24% | 83.33% | 88.89% |

*2026-07-26 に再現確認。OpenSSL の FP は別ソースが独自のバージョン体系で追跡している無関係な CVE であり（詳細は下記）、公式アドバイザリデータそのものの見逃しではない。OpenSSL の FN 2件（CVE-2025-9231/9232）は別途調査する価値のある実際のギャップ。*

*PostgreSQL の数値は、今回の調査で見つかった本番バグの修正を反映している——詳細はREADME.mdの[Known Issues「RHEL/Oracle Linuxのモジュールストリームによる偽陽性」](README.ja.md#rheloracle-linuxのモジュールストリームによる偽陽性根本原因を修正済みnodejspostgresql以外は一部残存)参照。当初5件のFP・FN無し（82.76%/100.00%/90.57%）だったうち4件は、RHEL/Oracle LinuxのOVALデータがDNFモジュールストリーム製品のバージョン下限を持たないという本物のバグだった（新しい系統向けの修正が無関係な古い16系統のクエリまで巻き込んでいた）。まず`ecosystem`未指定のデフォルト検索からモジュールストリーム行を除外して修正（これでNVD側に代替データの無かった正しい検知4件も失われ、新たなFNになった）、その後行ごとの下限推定で正式に修正。残る1件のFP（CVE-2017-8806）は無関係な本物のNVD製品名誤マッピング（Debianのラッパースクリプトパッケージ`postgresql-common`が製品名"postgresql"に対応付けられている）。上記の表はいずれも`ecosystem=`指定クエリを検証していない（`validate:postgresql`は未指定のデフォルト経路のみ）。*

*RHEL/Oracle Linuxの`versionStart`根本修正（OVALのModule criterionから直接抽出——上記[Node.js節](#境界値スイープnodejsモジュールストリーム--rhel--oracle-linux)参照）はpostgresqlにも自動適用され、以前の製品固有ヒューリスティックを置き換えた。nodejsのbare行問題を調査した際、postgresqlにも同種のバグが見つかり、スイープではなく生クエリで確認した（`validate-postgresql.ts`には`ecosystem=`指定パスのスイープモードが無いため）: `package=postgresql&version=9.2.10&ecosystem=oracle-linux`が56件ヒットし、その中には無関係な`13.23-2.el9_7`（RHEL9）でしか記録の無いCVE-2026-2004/2005/2006が含まれていた——Module criterionを一切持たないbare行（RHEL7はDNFモジュール化以前のOS`9.2.24-9.0.7.el7_9`、RHEL9/OL9はモジュール化前ベースライン`13.23-5.el9_8`、RHEL10/OL10はpostgresqlをモジュール化せず単一配布`16.14-1.0.1.el10_2`）に依然として下限が無かったため。`inferBareVersionStart()`が`postgresql`にも対応し、同じクエリが34件に減った。*

*さらに1点補正が必要だった: PostgreSQLはバージョン10より前は2桁がメジャーバージョン（`9.0`〜`9.6`、それぞれ互換性の無い別物）のため、先頭1桁だけのフロアでは`9.2.24-...`と`9.6.20-...`が同じ`9.0`に衝突していた——CVE-2019-10130（自身のRHSAが「postgresql:9.6 security update」）が`9.2.10`クエリに誤って一致することで発覚。`inferBareVersionStart()`は`9.x`系統を`9.0`ではなく完全な`9.{minor}`にフロアするよう修正した。両方の修正後、同じクエリは29件になり全て正真正銘`9.2.x`系統内に収まる。念のため`9.6.19`でクエリするとCVE-2019-10130（`9.6.20`で修正）は引き続き正しく検知され、同系統内のRecallは犠牲になっていない。*

*`httpd`は例外なく2桁のフロアが必要だった——1桁だけで安全な範囲が全く無い: RHEL/Oracle Linuxが追跡する範囲でApacheが単純な整数メジャーを使ったことは一度も無く、`2.2`（RHEL5/6、upstreamでは2018年にEOL）と`2.4`（RHEL7以降）だけで、Oracle Linuxではどちらもbare行（Module criterionが無い）だった。`package=httpd&version=2.2.3&ecosystem=oracle-linux`は修正前154件ヒットし、うち104件（68%）が無関係な`2.4.x`系統でしか修正されていないものだった。`inferBareVersionStart()`が`2.2`/`2.4`まで含めてフロアするようになり、同じクエリは57件になり全て正真正銘`2.2.x`系統。念のため`2.4.36`でクエリするとCVE-2020-11984（`2.4.37`で修正）は引き続き正しく検知される。RHEL/Oracle Linux向けの`validate-httpd`スイープはまだ無く（`validate:apache`はhttpd.apache.org自身のアドバイザリを検証するもので、このRHEL/Oracle LinuxのOVAL経路とは無関係）、上記postgresqlの数値と同じく`validate-nodejs.ts`ほど厳密にスイープされたものではなく生クエリでの確認に留まる。*

*`mysql`/`mariadb`はbare行の問題ですらなく、根本修正そのものの抜け穴だった: 実際のOVALフィードはドット付きのモジュールストリームラベル（`"Module mysql:8.4 is enabled"`、`"Module mariadb:10.11 is enabled"`）を使うが、`extractModuleMajor()`の元の正規表現は数字のみを想定しており、これらを黙って抽出し損ねていた——該当行は汎用の`.module+`バックフィルの単純な先頭1桁抽出に回り、mysqlの`8.0`/`8.4`系統、mariadbの`10.3`/`10.5`/`10.11`/`11.8`系統がそれぞれ同じフロアに衝突していた。`extractModuleMajor()`がストリームラベルを（数字限定ではなく、空白以外の任意のトークンとして）そのまま抽出するよう修正した。実際に確認: `package=mysql&version=8.0.30&ecosystem=oracle-linux`と`package=mariadb&version=10.3.30&ecosystem=oracle-linux`は、それぞれ同系統内の結果のみ返すようになった（362件・50件、他系統からの混入0件）。`mysql@8.4.0`も引き続き自系統を正しく検知する。両製品とも、postgresql/httpdと同じ2桁の`inferBareVersionStart()`フォールバックが必要な、DNF以前の古いbare系統も持つ——mysqlのRHEL5/6era`5.0`/`5.1`、mariadbのRHEL7era`5.5`——`package=mysql&version=5.1.60&ecosystem=oracle-linux`（70件、全て`5.1.x`）で確認済み。どちらも専用のスイープは無く、上記と同じく生クエリでの確認に留まる。*

*`php`も同じドット付きモジュールストリームラベル（`"Module php:8.1 is enabled"`）を使っており、上記の`extractModuleMajor()`修正で自動的にカバーされていた。加えて、DNFモジュール化以前の古いbare系統`5.1`/`5.3`（RHEL5/6）を持ち、`package=php&version=5.1.6&ecosystem=oracle-linux`で確認済み: 修正前は180件ヒットしうち134件（74%）が無関係な`5.3.x`系統への誤検知、修正後は59件（他系統からの混入0件）。`mysql`/`mariadb`/`php`はいずれも、同じソースRPM由来で親パッケージと全く同じバージョン文字列を共有するサブパッケージ（`mysql-server`、`mariadb-bench`、`php-cli`等）を多数持つ——`inferBareVersionStart()`はこれらもカバーするようになり、`package=php-cli&version=5.3.3&ecosystem=oracle-linux`（76件、他系統混入0件）と`package=mysql-server&version=5.1.60&ecosystem=oracle-linux`（70件、混入0件）で確認済み。一部のサブパッケージは独自のバージョン体系を持つため意図的に除外している（`mysql-selinux`のSELinuxポリシーバージョン、`mariadb-connector-c`のクライアントライブラリバージョン、PHPの`php-pecl-*`/`php-pear`/`php-libguestfs`等）——確認済みの完全なメンバーリストは`inferBareVersionStart()`のdocコメント参照。RHEL6/7時代のSoftware Collectionsパッケージ（`php54-php-cli`、`mysql55-mysql-server`等）は修正不要——バージョン自体がパッケージ名に埋め込まれているため、そもそも構造的にこの衝突から隔離されている。*

## 既知の制限事項

### 複数ソース間でのバージョン namespace 衝突（package=openssl 等）

`openssl`/`nginx` のように、同じ製品名を複数のソースが別々のバージョン体系で追跡しているケースがある（RHEL/Oracle Linux は同じ製品名で RPM の Epoch:Version-Release 形式のパッケージを別途配布している）。`package=X&version=Y` で検索すると、その製品名を追跡している**全ソース**の結果が返るため、1ソースの公式アドバイザリだけを正解として比較すると、無関係な別ソースのバージョン範囲と数値的に衝突して過検知に見えることがある。これは各ソースの fetcher 自体のバグではない。

専用の `AdvisoryFetcher` を持つ製品（nginx、Tomcat、Apache HTTP Server）については、[境界値スイープ](#境界値スイープnginx--tomcat--apache)のスクリプトが結果を該当 fetcher 自身の `sources` に絞り込んで測定しているため、この現象があっても Precision 100% を示す。

OpenSSL には専用 fetcher が無く（NVD/OSV のみでカバー）、絞り込める対象が無いことに加えてもう一段の制約が重なる。NVDのCPEバージョン範囲表現は「ブランチA・C・Dは影響を受けるが、既にEOLしたブランチBは対象外」という"歯抜け"を表現できず、単一の連続範囲でしか表せない。そのため、複数の現行ブランチに同時に影響する最近のCVEが、数値上たまたま既にEOLした古いブランチのバージョン番号まで含んでしまう。この理由により `validate:openssl` は意図的に自動スイープモードを持たない。単一バージョン検証を使い、この製品自体のアドバイザリ取り込みの欠陥ではなく、エンドポイント全体に共通するこの特性由来のPrecisionノイズがあることを前提に見てほしい。

PostgreSQLも専用fetcherが無く、原理上は同じNVD側の制約を抱えているが、実際のFPは上記とは異なる、より具体的な原因だったことが判明した——詳細は上記の[RHEL/Oracle Linuxのモジュールストリームによる偽陽性](README.md#rheloracle-linuxのモジュールストリームによる偽陽性デフォルト検索は対処済みpostgresqlは正式修正済み)を参照。

### RHEL/Oracle Linux の OVAL フィードは後から改訂されることがある

Red Hat や Oracle は、CVE番号やエラータ番号を変えないまま、公開済みのアドバイザリの影響パッケージ一覧を後から改訂することがある（サブパッケージの追加・削除など）。[境界値スイープ](#境界値スイープrhel--oracle-linux)はレポート作成時にground truthをライブ取得するが、DB側は直近の定期インポート時点のスナップショットを反映しているため、両者の間に少数の不一致が生じるのは想定内であり、次回のインポートで自然に解消する——検索やfetcherの欠陥ではない。実際に不一致のあった複数のCVEについてライブフィードを再取得し、影響パッケージ一覧がDBの内容から実際に変わっていることを確認済み。
