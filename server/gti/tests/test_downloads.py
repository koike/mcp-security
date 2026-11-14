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
from unittest import mock

import pytest
import vt
from mcp.server.fastmcp import Context
from mcp.server.fastmcp.exceptions import ToolError

from gti_mcp.tools import downloads


pytestmark = pytest.mark.asyncio(loop_scope="session")

SHA256_A = "a" * 64
SHA256_B = "b" * 64
ZIP_ID = "4939392292"
SIGNED_URL = (
    "https://samples.example.test/object?Signature=a%2Fb%2Bc%3D"
    "&Expires=2000000000&other=one+two"
)


@pytest.fixture(autouse=True)
def reset_httpserver(make_httpserver_ipv4):
  make_httpserver_ipv4.clear()
  yield
  make_httpserver_ipv4.check_assertions()
  make_httpserver_ipv4.clear()


@pytest.fixture
def ctx():
  return mock.MagicMock(spec=Context)


def zip_response(
    status="starting", files_ok=0, files_error=0, progress=0,
):
  return {
      "data": {
          "type": "zip_file",
          "id": ZIP_ID,
          "attributes": {
              "status": status, "progress": progress,
              "files_ok": files_ok, "files_error": files_error,
          },
      },
  }


def expect_json(httpserver, path, payload, method="GET", body=None, status=200):
  kwargs = {"method": method, "headers": {"X-Apikey": "dummy_api_key"}}
  if body is not None:
    kwargs["json"] = body
  httpserver.expect_request("/api/v3" + path, **kwargs).respond_with_json(
      payload, status=status)


async def test_file_url_preserves_signature_and_normalizes_hash(
    make_httpserver_ipv4, ctx,
):
  httpserver = make_httpserver_ipv4
  expect_json(httpserver, f"/files/{SHA256_A}/download_url", {"data": SIGNED_URL})

  result = await downloads.get_file_download_url("  " + SHA256_A.upper() + "\n", ctx)

  assert result == {
      "sha256": SHA256_A,
      "download_url": SIGNED_URL,
      "expires_in_seconds": 3600,
  }
  assert len(httpserver.log) == 1
  httpserver.check_assertions()


async def test_create_zip_payload_password_and_ordered_deduplication(
    make_httpserver_ipv4, ctx, caplog,
):
  httpserver = make_httpserver_ipv4
  password = "supplied-password: keep exact spaces "
  expect_json(
      httpserver, "/intelligence/zip_files", zip_response(), method="POST",
      body={"data": {"hashes": [SHA256_B, SHA256_A], "password": password}},
  )

  result = await downloads.create_sample_zip(
      [SHA256_B.upper(), SHA256_A, " " + SHA256_B + " "], ctx, password,
  )

  assert result == {
      "zip_id": ZIP_ID,
      "status": "starting", "progress": 0,
      "files_ok": 0, "files_error": 0,
      "ready": False, "partial": False,
      "hashes": [SHA256_B, SHA256_A], "zip_password": password,
  }
  assert password not in caplog.text
  assert "dummy_api_key" not in str(result)
  assert len(httpserver.log) == 1
  httpserver.check_assertions()


async def test_create_single_sample_zip_generates_random_password(
    make_httpserver_ipv4, ctx, monkeypatch,
):
  httpserver = make_httpserver_ipv4
  token = "random-password-from-secrets-token"
  token_generator = mock.Mock(return_value=token)
  monkeypatch.setattr(downloads.secrets, "token_urlsafe", token_generator)
  expect_json(
      httpserver, "/intelligence/zip_files", zip_response(), method="POST",
      body={"data": {"hashes": [SHA256_A], "password": token}},
  )

  result = await downloads.create_sample_zip([SHA256_A], ctx)

  token_generator.assert_called_once_with(24)
  assert result["zip_password"] == token
  assert result["hashes"] == [SHA256_A]
  httpserver.check_assertions()


async def test_zip_status_reports_partial_completion(make_httpserver_ipv4, ctx):
  httpserver = make_httpserver_ipv4
  expect_json(
      httpserver, f"/intelligence/zip_files/{ZIP_ID}",
      zip_response("finished", files_ok=2, files_error=1, progress=100),
  )

  result = await downloads.get_sample_zip_status(ZIP_ID, ctx)

  assert result == {
      "zip_id": ZIP_ID, "status": "finished", "progress": 100,
      "files_ok": 2, "files_error": 1, "ready": True, "partial": True,
  }
  assert len(httpserver.log) == 1
  httpserver.check_assertions()


@pytest.mark.parametrize("status", ["starting", "creating", "timeout", "error-starting", "error-creating"])
async def test_zip_url_not_ready_does_not_issue_url(make_httpserver_ipv4, ctx, status):
  httpserver = make_httpserver_ipv4
  expect_json(
      httpserver, f"/intelligence/zip_files/{ZIP_ID}", zip_response(status),
  )

  result = await downloads.get_sample_zip_download_url(ZIP_ID, ctx)

  assert result["status"] == status
  assert result["ready"] is False
  assert "download_url" not in result
  assert "expires_in_seconds" not in result
  assert len(httpserver.log) == 1
  httpserver.check_assertions()


@pytest.mark.parametrize("files_error", [0, 1])
async def test_finished_zip_url_includes_status_and_ttl(
    make_httpserver_ipv4, ctx, files_error,
):
  httpserver = make_httpserver_ipv4
  expect_json(
      httpserver, f"/intelligence/zip_files/{ZIP_ID}",
      zip_response("finished", files_ok=2, files_error=files_error, progress=100),
  )
  expect_json(
      httpserver, f"/intelligence/zip_files/{ZIP_ID}/download_url",
      {"data": SIGNED_URL},
  )

  result = await downloads.get_sample_zip_download_url(ZIP_ID, ctx)

  assert result["ready"] is True
  assert result["files_ok"] == 2
  assert result["files_error"] == files_error
  assert result["partial"] is bool(files_error)
  assert result["download_url"] == SIGNED_URL
  assert result["expires_in_seconds"] == 3600
  assert "zip_password" not in result
  assert len(httpserver.log) == 2
  httpserver.check_assertions()


@pytest.mark.parametrize(
    "tool_name, arguments, path, method",
    [
        ("get_file_download_url", {"sha256": SHA256_A},
         f"/files/{SHA256_A}/download_url", "GET"),
        ("create_sample_zip", {"hashes": [SHA256_A], "password": "zip-password"},
         "/intelligence/zip_files", "POST"),
        ("get_sample_zip_status", {"zip_id": ZIP_ID},
         f"/intelligence/zip_files/{ZIP_ID}", "GET"),
        ("get_sample_zip_download_url", {"zip_id": ZIP_ID},
         f"/intelligence/zip_files/{ZIP_ID}", "GET"),
    ],
)
@pytest.mark.parametrize(
    "http_status, code",
    [(403, "ForbiddenError"), (429, "QuotaExceededError"), (404, "NotFoundError")],
)
async def test_upstream_errors_keep_code_without_message_or_secrets(
    make_httpserver_ipv4, ctx, caplog,
    tool_name, arguments, path, method, http_status, code,
):
  httpserver = make_httpserver_ipv4
  private_message = "do-not-return: api-key=private-key password=zip-password"
  expect_json(
      httpserver, path,
      {"error": {"code": code, "message": private_message}},
      method=method, status=http_status,
  )

  with pytest.raises(ToolError) as caught:
    await getattr(downloads, tool_name)(ctx=ctx, **arguments)

  assert str(caught.value) == "GTI API error: " + code
  assert private_message not in str(caught.value)
  assert private_message not in caplog.text
  assert caught.value.__suppress_context__ is True
  assert len(httpserver.log) == 1
  httpserver.check_assertions()


async def test_finished_zip_url_api_error_is_not_an_empty_success(
    make_httpserver_ipv4, ctx,
):
  httpserver = make_httpserver_ipv4
  expect_json(
      httpserver, f"/intelligence/zip_files/{ZIP_ID}",
      zip_response("finished", files_ok=1, progress=100),
  )
  expect_json(
      httpserver, f"/intelligence/zip_files/{ZIP_ID}/download_url",
      {"error": {"code": "QuotaExceededError", "message": "private"}}, status=429,
  )

  with pytest.raises(ToolError, match="QuotaExceededError"):
    await downloads.get_sample_zip_download_url(ZIP_ID, ctx)

  assert len(httpserver.log) == 2
  httpserver.check_assertions()


@pytest.mark.parametrize(
    "tool_name, arguments",
    [
        ("get_file_download_url", {"sha256": "a" * 32}),
        ("get_file_download_url", {"sha256": "g" * 64}),
        ("get_file_download_url", {"sha256": SHA256_A + "/download"}),
        ("create_sample_zip", {"hashes": []}),
        ("create_sample_zip", {"hashes": SHA256_A}),
        ("create_sample_zip", {"hashes": ["not-a-hash"]}),
        ("create_sample_zip", {"hashes": [SHA256_A] * 101}),
        ("create_sample_zip", {"hashes": [SHA256_A], "password": ""}),
        ("create_sample_zip", {"hashes": [SHA256_A], "password": "\x00password"}),
        ("create_sample_zip", {"hashes": [SHA256_A], "password": "x" * 1025}),
        ("get_sample_zip_status", {"zip_id": "../files"}),
        ("get_sample_zip_status", {"zip_id": "zip%2Fdownload"}),
        ("get_sample_zip_download_url", {"zip_id": "zip?key=secret"}),
        ("get_sample_zip_download_url", {"zip_id": ""}),
    ],
)
async def test_invalid_inputs_fail_before_request(
    make_httpserver_ipv4, ctx, tool_name, arguments,
):
  with pytest.raises(ToolError):
    await getattr(downloads, tool_name)(ctx=ctx, **arguments)
  assert make_httpserver_ipv4.log == []


@pytest.mark.parametrize(
    "url",
    [
        "http://samples.example.test/file",
        "https:///file", "https://", "https://user:secret@samples.example.test/file",
        "https://samples.example.test/file\n?token=secret",
        "https://samples.example.test:bad/file", "file:///tmp/sample", None,
    ],
)
async def test_invalid_download_url_is_rejected_without_echoing(
    make_httpserver_ipv4, ctx, url,
):
  expect_json(
      make_httpserver_ipv4, f"/files/{SHA256_A}/download_url", {"data": url},
  )

  with pytest.raises(ToolError) as caught:
    await downloads.get_file_download_url(SHA256_A, ctx)

  assert "secret" not in str(caught.value)
  assert "samples.example" not in str(caught.value)


@pytest.mark.parametrize(
    "payload",
    [
        {}, {"data": None}, {"data": "private"},
        {"data": {"type": "zip_file", "id": "../files", "attributes": {}}},
        {"data": {"type": "zip_file", "id": "wrong-job", "attributes": {
            "status": "finished", "files_ok": 1, "files_error": 0,
        }}},
        {"data": {"type": "zip_file", "id": ZIP_ID, "attributes": {
            "status": "finished", "files_ok": -1, "files_error": 0,
        }}},
    ],
)
async def test_malformed_zip_state_does_not_issue_url(
    make_httpserver_ipv4, ctx, payload,
):
  expect_json(make_httpserver_ipv4, f"/intelligence/zip_files/{ZIP_ID}", payload)

  with pytest.raises(ToolError):
    await downloads.get_sample_zip_download_url(ZIP_ID, ctx)

  assert len(make_httpserver_ipv4.log) == 1


@pytest.mark.parametrize(
    "exception",
    [
        vt.APIError("secret https://private/?api-key=hidden", "private message"),
        vt.APIError("secret" + "a" * 58, "private message"),
        RuntimeError("private transport info api-key=hidden"),
    ],
)
async def test_nonstandard_errors_do_not_expose_private_details(ctx, exception, caplog):
  with mock.patch.object(downloads, "vt_client", side_effect=exception):
    with pytest.raises(ToolError) as caught:
      await downloads.get_file_download_url(SHA256_A, ctx)
  assert "private" not in str(caught.value)
  assert "hidden" not in str(caught.value)
  assert "secret" not in str(caught.value)
  assert "private" not in caplog.text
