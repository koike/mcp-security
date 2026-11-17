# Retrohuntと検体取得URLの追加ツール

このブランチは、`google/mcp-security`のGTI MCPサーバーに、既存Retrohuntの結果取得と検体のダウンロードURL発行を追加する非公式拡張です。上流の基準は[`bc045e29c7ba93f16b6675e51d2147885821d91f`](https://github.com/google/mcp-security/tree/bc045e29c7ba93f16b6675e51d2147885821d91f/server/gti)です。既存の`search_iocs`と組み合わせて、Content Searchのヒットから取得対象を選べます。

この実装はVT側でパスワード付きZIPを作成し、署名付きURLを返します。検体本体やZIP本体をMCPサーバーに保存したり、MCP経由で転送したりする機能はありません。実ファイルの取得と解析は、呼び出し元の環境で行います。

## 投稿・コレクション更新機能の削除

このブランチでは、次の4ツールを関数本体とMCPの登録から削除しています。

- `analyse_file`
- `create_collection`
- `update_collection_attributes`
- `update_iocs_in_collection`

公開ツールは39件です。削除した名前は`tools/list`に含まれず、名前を直接指定した`tools/call`も`Unknown tool`エラーになります。ファイル投稿やコレクションへの書き込みを行うための代替ツールは追加していません。

Content Search、既存Retrohuntの結果取得、ファイル・URL・ドメイン・IPのレポート取得、Telemetryの投稿履歴、既存コレクションの検索・閲覧、検体のダウンロードURL発行は引き続き利用できます。`get_url_report`は取得エラー時にURL投稿や再解析へ切り替えません。

DTM検索の`POST /dtm/docs/search`と、既存検体のZIP作成の`POST /intelligence/zip_files`も維持しています。ZIP作成はVT側で新しいZIPオブジェクトを作る操作であり、ローカルの検体本体をアップロードする操作ではありません。この変更はHTTPのPOST全般を禁止するものではありません。

検索式や照会する識別子はVTへ送信されます。[検索APIの公式ドキュメント](https://docs.virustotal.com/reference/intelligence-search)には、APIで投稿または照会したIoCのスキャン・データセットへの追加に関する注意書きがあります。今回の削除はMCP側の投稿・更新処理を取り除くもので、VT側が照会IoCを登録・スキャンしないことを保証するものではありません。

## セットアップ

Python 3.11以上、Git、[uv](https://docs.astral.sh/uv/getting-started/installation/)が必要です。ランタイム依存は`pyproject.toml`の`mcp>=1.23.0,<2.0`と`vt-py`を使用します。以下はLinux/macOSのBashで、新しいチェックアウトへ導入する例です。このforkでは`main`を上流に合わせるために保持し、追加機能を`gti-retrohunt-download-tools`ブランチで管理します。

```bash
git clone --branch gti-retrohunt-download-tools https://github.com/koike/mcp-security.git
cd mcp-security/server/gti
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e .
```

仮想環境とeditable installの指定はuvの標準機能です。既にclone済みの場合は対象ブランチへ切り替え、同じ`server/gti`ディレクトリで導入します。[uv：環境の作成](https://docs.astral.sh/uv/pip/environments/)、[uv：パッケージの導入](https://docs.astral.sh/uv/pip/packages/)

APIキーはサーバープロセスの環境変数`VT_APIKEY`で渡します。対話シェルで入力する例です。

```bash
read -r -s -p 'VT_APIKEY: ' VT_APIKEY
printf '\n'
export VT_APIKEY
.venv/bin/gti_mcp
```

`gti_mcp`はstdioのMCPサーバーとして動作します。MCPクライアントから起動する場合は、この仮想環境内の`gti_mcp`を起動コマンドに指定し、そのプロセスへ`VT_APIKEY`が渡るように設定してください。APIキーをツール引数やソースコードに含める必要はありません。クライアント固有の設定は[既存README](README.md)も参照してください。

### 既存環境の更新

このforkをGitで取得している場合は、リポジトリのルートで対象ブランチを更新します。未コミットの変更がある場合は差分を確認し、作業内容を保持してから実行してください。

```bash
git switch gti-retrohunt-download-tools
git pull --ff-only origin gti-retrohunt-download-tools
```

上記のセットアップ例と同じ仮想環境を使っている場合は、続いてパッケージを更新します。

```bash
cd server/gti
uv pip install --python .venv/bin/python -e .
```

別の仮想環境で運用している場合は、そのPythonとチェックアウトを指定してください。更新後は、稼働中のMCPサーバープロセスを現在の起動方法で再起動します。クライアント側でツール一覧を再取得し、39件であることと、削除した4ツールが含まれないことを確認してください。ソースの更新だけでは既に起動済みのプロセスに残る登録は変わりません。

## 追加した7ツール

表の引数はMCP呼び出し元が指定するものです。`ctx`は内部で供給されます。

| ツール | 引数 | 主な戻り値 |
| --- | --- | --- |
| `list_retrohunt_jobs` | `limit=10`、任意の`cursor`・`status` | `jobs`とページング情報 |
| `get_retrohunt_job` | `job_id`、`include_rules=false` | ジョブの属性、ルールのSHA-256とバイト数。指定時のみルール本文 |
| `get_retrohunt_matches` | `job_id`、`limit=10`、任意の`cursor` | `files`、`job_id`とページング情報 |
| `get_file_download_url` | `sha256` | `sha256`、`download_url`、`expires_in_seconds` |
| `create_sample_zip` | `hashes`、任意の`password` | ZIP状態、`zip_id`、正規化後の`hashes`、`zip_password` |
| `get_sample_zip_status` | `zip_id` | `status`、`progress`、`files_ok`、`files_error`、`ready`、`partial`、`zip_id` |
| `get_sample_zip_download_url` | `zip_id` | ZIP状態。完成していれば`download_url`と`expires_in_seconds`も返す |

### Content Searchとの連携

既存`search_iocs`に、通常のGTI検索構文で`content:`を渡します。以下は説明用の検索文字列です。

ツール：`search_iocs`

```json
{
  "query": "type:peexe content:\"UniqueProtocolMarker-v1\"",
  "limit": 10
}
```

結果のファイルオブジェクトからSHA-256を選び、取得ツールへ渡します。ファイルの`id`はSHA-256です。[公式：Files](https://docs.virustotal.com/reference/files)

Content SearchではVT APIの`order`が無効なため、`order_by`による並べ替えを前提にしないでください。既存`search_iocs`の実装は変更しておらず、検索用の`next_cursor`やsnippet本文の専用取得ツールは今回追加していません。[公式：Advanced corpus search](https://docs.virustotal.com/reference/intelligence-search)

### Retrohuntの結果を読む

まず`list_retrohunt_jobs`でジョブを選び、必要に応じて`get_retrohunt_job`で状態を確認します。`status`フィルタは`starting`、`running`、`aborting`、`aborted`、`finished`に対応しています。[公式：Get a list of Retrohunt jobs](https://docs.virustotal.com/reference/get-retrohunt-jobs)

ツール：`get_retrohunt_matches`。`<job-id>`は一覧で取得した実値に置き換えます。

```json
{
  "job_id": "<job-id>",
  "limit": 40
}
```

一覧と一致検体の両ツールで、`limit`は1〜40です。APIの上限に合わせてページサイズを制限しています。返却する`returned_count`は今回の件数、`total_count`は上流の`meta.count`が存在した場合だけ返す値です。`has_more=true`なら、`next_cursor`を変更せず次回の`cursor`へ渡します。ジョブIDと絞り込み条件を維持し、cursorをデコード・再生成しないでください。継続情報に矛盾がある応答はエラーとして扱います。

一致ファイルはSHA-256と実用的な属性に絞り、上流にあれば`context_attributes.rule_name`と`match_in_subfile`を保持します。エンジン別の大きな解析結果は除外し、`names`は最大10件です。

ルール本文は既定で返しません。`get_retrohunt_job`に`include_rules=true`を指定すると、最大65,536文字の`attributes.rules`と`rules_truncated`を返します。`rules_sha256`と`rules_bytes`はUTF-8のルール全文に対する値です。Retrohuntのジョブと一致結果は所有者のアクセス権で取得します。この追加機能は既存ジョブの読み取り用です。[公式：Retrohunt Jobの属性とアクセス範囲](https://docs.virustotal.com/reference/retrohunt-job-matching-files)

## raw検体またはZIPのURLを取得する

以下の`<sha256>`と`<zip-id>`は、検索・API応答で得た実値に置き換えます。

### raw検体

`get_file_download_url`を次の引数で呼びます。

```json
{
  "sha256": "<sha256>"
}
```

返却された`download_url`を、呼び出し元の解析環境でそのまま使用します。APIキーを取得先へ付加する必要はありません。URLのクエリやエスケープを変更すると署名が無効になる可能性があります。

### パスワード付きZIP

1. `create_sample_zip`へ`{"hashes": ["<sha256>"]}`を渡します。1検体でも利用できます。
2. 応答の`zip_id`と`zip_password`を保持します。`password`を省略すると乱数から生成します。パスワードは作成時だけ返し、後続ツールでの再取得やサーバーでの永続保存は行いません。
3. `get_sample_zip_status`へ`{"zip_id": "<zip-id>"}`を渡します。自動ポーリングは行わないため、必要なら間隔を空けて再確認します。
4. `get_sample_zip_download_url`へ同じIDを渡します。状態を1回確認し、`status=finished`ならURLを発行します。未完成なら状態だけを返します。
5. 解析環境でZIPを取得し、保持した`zip_password`で展開します。

`hashes`の入力は1〜100件です。**100件はこの実装の運用上限であり、VT APIの上限ではありません。** 入力件数を検査した後、SHA-256の前後空白・大文字小文字を正規化し、順序を保って重複を除きます。指定するパスワードは空文字列とNULを拒否し、最大1,024文字です。[公式：ZIP作成API](https://docs.virustotal.com/reference/create-zip-files)

`ready=true`は`status=finished`を意味します。`files_ok`と`files_error`も確認してください。`partial=true`は完成時に成功・失敗の両方がある場合だけであり、`partial=false`だけでは全件成功を意味しません。完成したZIPに一部失敗があってもURL発行を行います。[公式：ZIPの状態](https://docs.virustotal.com/reference/get-zip-files)

ZIP作成は状態を変更する操作です。送信後のタイムアウトでは、VT側で作成が始まったか不明な場合があるため、**作成要求を無条件に自動再試行しないでください**。この実装自体も自動再送しません。

## 権限、クォータ、取得後の確認

APIキーの権限とクォータが各操作に適用されます。追加ツールのAPIエラーは`ToolError`として返し、正常な空結果と区別します。既知のエラーコードを残し、上流のエラー本文や接続例外の詳細は返しません。403・404・429などの扱いは[VTのエラー仕様](https://docs.virustotal.com/reference/errors)を参照してください。

ファイル・ZIPの署名URLは1時間で失効し、ツールは`expires_in_seconds: 3600`を返します。**単一ファイルのURL発行は、実ダウンロードを行わなくてもダウンロードクォータを消費します。** 同じ有効なURLによる再取得は追加のダウンロードクォータを消費しません。検索、状態確認、ZIP作成などのAPIアクセスも、アカウントの制限を考慮して行ってください。[公式：ファイルURL](https://docs.virustotal.com/reference/files-download-url)、[公式：ZIP URL](https://docs.virustotal.com/reference/zip-files-download-url)

URLが発行されても、呼び出し元へ検体が到着したとは限りません。ChatGPTなどの実行環境では、接続先やファイルの受け入れが制限される場合があります。この拡張は実通信・マルウェアの受け入れ・ZIPの展開互換性を保証せず、制限を迂回する転送機能も提供しません。

取得できたraw検体はSHA-256を照合します。ZIPではアーカイブ自体のハッシュと検体のハッシュを区別し、展開した各検体を要求したSHA-256一覧と照合してください。その後、検体を実行せずにファイル形式、文字列、ヘッダー、インポート、スクリプト内容などの静的解析を行います。署名URLと`zip_password`は一時的な取得・展開権限として扱い、公開リポジトリや調査に不要な共有先へ含めないでください。

## 起動時の警告

MCP SDK 1.xと`pydantic-settings>=2.15`の組み合わせでは、`lifespan`の型参照が未解決であることを示す`IncompleteFieldDefinitionWarning`が出る場合があります。このブランチではFastMCPの生成前に`Settings.model_rebuild()`を呼び、設定の読み込み前に型参照を解決しています。[MCP SDKの既知の問題と回避策](https://github.com/modelcontextprotocol/python-sdk/issues/3294)

DTM検索の説明文に含まれるバックスラッシュはraw文字列で記述し、Python 3.12の`SyntaxWarning: invalid escape sequence`を解消しています。ツールへ公開する説明文の内容は変更していません。

古いコードでこれらの警告が表示されても、続いてツール一覧が39件取得できていれば、その一覧確認は成功しています。警告を一括で非表示にする設定は不要です。Gitでソースを更新した後、起動済みのMCPプロセスを再起動してください。

## テスト

`server/gti`でテスト用依存を導入し、実行します。テストはモックとローカルHTTPサーバーを使用し、実APIキーや実検体を必要としません。

```bash
uv pip install --python .venv/bin/python -e '.[test]'
.venv/bin/python -m pytest -q tests
```

4ツール削除後の確認結果は次のとおりです。

| 対象 | 環境 | 結果 |
| --- | --- | --- |
| 全テスト | Python 3.12.14、MCP SDK 1.29.0、vt-py 0.22.0 | 181件成功 |
| MCPプロトコルと初回起動の回帰テスト | Python 3.12.14、MCP SDK 1.23.0、vt-py 0.22.0 | 11件成功 |
| stdioの実プロセス接続 | MCP SDK 1.29.0、実APIキーなし | 39ツールを確認。削除した4ツールの呼び出しは`Unknown tool` |

削除対象の旧テスト13件を除き、新しい回帰テスト7件を追加しました。ツール一覧が残る39件と一致すること、削除した4名を指定してもVTクライアントを生成せず拒否すること、URL取得が404でも投稿へ切り替えないこと、Content Searchの結果を取得できることを確認しています。

さらに初回起動の回帰テスト1件を追加し、別のPythonプロセスと新しいバイトコードキャッシュを使って、今回の2種類の警告をエラー扱いにしても39件のツールを取得できることを確認しています。初回起動の確認ではVTクライアントを生成しません。

SDK下限でMCPプロトコルと初回起動の回帰テストを確認する場合は、別の仮想環境を使えます。

```bash
uv venv --python 3.12 .venv-mcp123
uv pip install --python .venv-mcp123/bin/python -e '.[test]' 'mcp==1.23.0' 'vt-py==0.22.0'
.venv-mcp123/bin/python -m pytest -q tests/test_research_mcp.py tests/test_tool_removal.py tests/test_startup.py
```

APIペイロード、ページ送り、一致コンテキスト、入力検証、APIエラー、ZIPの状態遷移、MCPの登録・応答を確認しています。これらの自動テストとは別に、利用する実アカウントの権限と、呼び出し元からのファイル取得可否を確認してください。

## ライセンス

元プロジェクトの[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)を継承します。既存ソースの著作権表示を維持し、追加ソースもApache-2.0で公開します。この拡張はforkで提供するもので、GoogleまたはVirusTotalによる公式の機能追加・サポートを示すものではありません。
