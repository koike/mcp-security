# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""VT 側で検体の署名 URL とパスワード付き ZIP を発行する。"""

from contextlib import asynccontextmanager
import math
import re
import secrets
import typing
from urllib.parse import urlsplit

import vt
from mcp.server.fastmcp import Context
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from ..server import server, vt_client


__all__ = [
    "get_file_download_url", "create_sample_zip", "get_sample_zip_status",
    "get_sample_zip_download_url",
]


# この上限はツール側の運用方針であり、VirusTotal API の上限ではない。
MAX_ZIP_HASHES = 100
MAX_ZIP_PASSWORD_LENGTH = 1024
DOWNLOAD_URL_TTL_SECONDS = 3600
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ZIP_ID = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")
_SAFE_ERROR_CODES = frozenset({
    "APIError", "BadRequestError", "InvalidArgumentError", "NotFoundError",
    "AlreadyExistsError", "NotAvailableYet", "UnselectiveContentQueryError",
    "AccessDeniedError", "AuthenticationRequiredError", "WrongCredentialsError",
    "ForbiddenError", "QuotaExceededError", "TooManyRequestsError",
    "TransientError", "DeadlineExceededError", "FailedDependencyError",
    "UserNotActiveError", "ClientError", "ServerError", "UnknownError",
})
_ZIP_STATUSES = frozenset({
    "starting", "creating", "finished", "timeout",
    "error-starting", "error-creating",
})


def _normalize_sha256(value: str) -> str:
  if not isinstance(value, str):
    raise ToolError("sha256 は 64 桁の 16 進数で指定してください。")
  value = value.strip().lower()
  if not _SHA256.fullmatch(value):
    raise ToolError("sha256 は 64 桁の 16 進数で指定してください。")
  return value


def _normalize_hashes(hashes: list[str]) -> list[str]:
  if not isinstance(hashes, list) or not hashes:
    raise ToolError("hashes は 1 件以上の SHA-256 の配列で指定してください。")
  # 大きすぎる入力を先に拒否し、正規化後は出現順で重複を除く。
  if len(hashes) > MAX_ZIP_HASHES:
    raise ToolError(
        f"このツールでは hashes は 1 回 {MAX_ZIP_HASHES} 件までです。"
        "これはツール側の上限であり、VT API の上限ではありません。")
  return list(dict.fromkeys(_normalize_sha256(value) for value in hashes))


def _validate_zip_id(zip_id: str) -> str:
  if not isinstance(zip_id, str) or not _ZIP_ID.fullmatch(zip_id):
    raise ToolError(
        "zip_id は VT が返した ZIP の識別子を指定してください。"
        "このツールでは英数字、ハイフン、アンダースコアの 1〜256 文字を受け付けます。")
  return zip_id


def _zip_password(password: str | None) -> str:
  if password is None:
    return secrets.token_urlsafe(24)
  if not isinstance(password, str) or not password or "\x00" in password:
    raise ToolError("password は空文字列や NUL 文字を含まない文字列にしてください。")
  if len(password) > MAX_ZIP_PASSWORD_LENGTH:
    raise ToolError(
        f"このツールでは password は {MAX_ZIP_PASSWORD_LENGTH} 文字までです。")
  return password


@asynccontextmanager
async def _api_client(ctx: Context) -> typing.AsyncIterator[vt.Client]:
  """API のエラー本文・接続情報・秘密値をエラー表示に含めない。"""
  try:
    async with vt_client(ctx) as client:
      yield client
  except ToolError:
    raise
  except vt.APIError as error:
    code = error.code
    if not isinstance(code, str) or code not in _SAFE_ERROR_CODES:
      code = "APIError"
    raise ToolError(f"GTI API error: {code}") from None
  except Exception:
    raise ToolError("GTI API へのリクエストに失敗しました。") from None


def _download_url(payload: typing.Any) -> str:
  value = payload.get("data") if isinstance(payload, dict) else None
  if not isinstance(value, str) or not value:
    raise ToolError("GTI が返したダウンロード URL の形式が不正です。")
  try:
    parsed = urlsplit(value)
    valid = (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and not any(char.isspace() or ord(char) < 32 or ord(char) == 127
                    for char in value)
        and "\\" not in value
    )
    # 不正なポートを含む URL もここで拒否する。
    parsed.port
  except ValueError:
    valid = False
  if not valid:
    raise ToolError("GTI が返したダウンロード URL の形式が不正です。")
  # クエリの順序やエスケープを変えると署名が無効になり得る。
  return value


def _zip_status(
    payload: typing.Any, expected_zip_id: str | None = None,
) -> dict[str, typing.Any]:
  data = payload.get("data") if isinstance(payload, dict) else None
  if not isinstance(data, dict):
    raise ToolError("GTI が返した ZIP 状態の形式が不正です。")
  zip_id = data.get("id")
  attrs = data.get("attributes")
  if (not isinstance(zip_id, str) or not _ZIP_ID.fullmatch(zip_id)
      or (expected_zip_id is not None and zip_id != expected_zip_id)
      or data.get("type") != "zip_file" or not isinstance(attrs, dict)):
    raise ToolError("GTI が返した ZIP 状態の形式が不正です。")

  status = attrs.get("status")
  files_ok = attrs.get("files_ok")
  files_error = attrs.get("files_error")
  progress = attrs.get("progress")
  if (not isinstance(status, str) or status not in _ZIP_STATUSES
      or type(files_ok) is not int or files_ok < 0
      or type(files_error) is not int or files_error < 0
      or (progress is not None and (
          type(progress) not in (int, float)
          or not math.isfinite(progress) or not 0 <= progress <= 100))):
    raise ToolError("GTI が返した ZIP 状態の形式が不正です。")

  ready = status == "finished"
  return {
      "zip_id": zip_id,
      "status": status,
      "progress": progress,
      "files_ok": files_ok,
      "files_error": files_error,
      "ready": ready,
      "partial": ready and files_ok > 0 and files_error > 0,
  }


@server.tool(annotations=ToolAnnotations(
    readOnlyHint=False, destructiveHint=False,
    idempotentHint=False, openWorldHint=True))
async def get_file_download_url(
    sha256: str, ctx: Context,
) -> dict[str, typing.Any]:
  """単一検体の署名付きダウンロード URL を発行する。

  sha256 は対象検体の SHA-256。URL の有効期間は発行から 1 時間。
  URL 発行は VT のクォータを消費し、一時的なダウンロード権限を渡す。
  サーバーは検体をダウンロード・保存せず、API キーも返さない。
  返却した URL は呼び出し元の解析環境で直接ダウンロードに使用する。
  """
  sha256 = _normalize_sha256(sha256)
  async with _api_client(ctx) as client:
    payload = await client.get_json_async(f"/files/{sha256}/download_url")
    url = _download_url(payload)
  return {
      "sha256": sha256,
      "download_url": url,
      "expires_in_seconds": DOWNLOAD_URL_TTL_SECONDS,
  }


@server.tool(annotations=ToolAnnotations(
    readOnlyHint=False, destructiveHint=False,
    idempotentHint=False, openWorldHint=True))
async def create_sample_zip(
    hashes: list[str], ctx: Context, password: str | None = None,
) -> dict[str, typing.Any]:
  """選択した検体のパスワード付き ZIP を VT 側で非同期作成する。

  hashes は SHA-256 の配列。1 検体でも作成可能。入力は 1 回 100 件まで
  (このツールの運用上限であり VT API の上限ではない)。大文字・小文字を
  正規化し、順序を保持して重複を除く。password を省略すると安全な乱数で
  生成し、空文字列は拒否する。password はツール側の上限で 1024 文字まで。
  zip_password は作成時に返すので保持する。
  zip_id は ZIP ジョブの識別子で、検体の SHA-256 とは異なる。
  作成はクォータを消費する。応答待ちに失敗しても自動再試行しない。
  後続で get_sample_zip_status / get_sample_zip_download_url を使用する。
  このサーバーは検体バイトや ZIP を取得・保存しない。
  """
  hashes = _normalize_hashes(hashes)
  zip_password = _zip_password(password)
  async with _api_client(ctx) as client:
    response = await client.post_async(
        "/intelligence/zip_files",
        json_data={"data": {"hashes": hashes, "password": zip_password}},
    )
    error = await client.get_error_async(response)
    if error:
      raise error
    result = _zip_status(await response.json_async())
  return {**result, "hashes": hashes, "zip_password": zip_password}


@server.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False,
    idempotentHint=True, openWorldHint=True))
async def get_sample_zip_status(
    zip_id: str, ctx: Context,
) -> dict[str, typing.Any]:
  """VT が返した ZIP ジョブ ID から作成状況を 1 回取得する。

  ready=True は status=finished のとき。files_error がある場合も ZIP は
  完成し得るため、files_ok / files_error を必ず確認する。partial=True は
  完成した ZIP に取得成功と失敗の両方がある場合。自動ポーリングは行わない。
  """
  zip_id = _validate_zip_id(zip_id)
  async with _api_client(ctx) as client:
    payload = await client.get_json_async(f"/intelligence/zip_files/{zip_id}")
    return _zip_status(payload, expected_zip_id=zip_id)


@server.tool(annotations=ToolAnnotations(
    readOnlyHint=False, destructiveHint=False,
    idempotentHint=False, openWorldHint=True))
async def get_sample_zip_download_url(
    zip_id: str, ctx: Context,
) -> dict[str, typing.Any]:
  """ZIP の状態を確認し、完成していれば署名付き URL を発行する。

  最初に状態確認 API を 1 回呼ぶ。ready=False なら状態だけを返し、URL
  発行 API は呼ばない。完成時は状態と download_url、expires_in_seconds
  (発行から 3600 秒) を返す。files_error がある ZIP も取得可能。
  URL 発行はクォータを消費し、一時的なダウンロード権限を渡す。
  パスワードは作成時の zip_password を呼び出し元で使用する。
  サーバーは ZIP を取得・保存しない。
  """
  zip_id = _validate_zip_id(zip_id)
  async with _api_client(ctx) as client:
    payload = await client.get_json_async(f"/intelligence/zip_files/{zip_id}")
    result = _zip_status(payload, expected_zip_id=zip_id)
    if not result["ready"]:
      return result
    payload = await client.get_json_async(
        f"/intelligence/zip_files/{zip_id}/download_url")
    return {
        **result,
        "download_url": _download_url(payload),
        "expires_in_seconds": DOWNLOAD_URL_TTL_SECONDS,
    }
