# SPDX-License-Identifier: Apache-2.0
"""Retrohunt pagination, metadata, input validation, and error handling."""

from contextlib import asynccontextmanager
import hashlib
from unittest.mock import AsyncMock, MagicMock

import pytest
import vt
from mcp.server.fastmcp import Context
from mcp.server.fastmcp.exceptions import ToolError

from gti_mcp.tools import retrohunt


HASH = "a" * 64
JOB_ID = "analyst.name_1-1700000000"
RULES = 'rule example { condition: true }'


@pytest.fixture
def api(monkeypatch):
  client = MagicMock()
  client.get_json_async = AsyncMock()

  @asynccontextmanager
  async def connection(_ctx):
    yield client

  monkeypatch.setattr(retrohunt, "vt_client", connection)
  return client


@pytest.fixture
def ctx():
  return MagicMock(spec=Context)


def job():
  return {
      "id": JOB_ID, "type": "retrohunt_job",
      "attributes": {"status": "finished", "num_matches": 1, "rules": RULES},
  }


def matched_file(match_in_subfile=False):
  return {
      "id": HASH, "type": "file",
      "attributes": {
          "sha256": HASH, "size": 123, "names": [f"name-{i}" for i in range(15)],
          "last_analysis_stats": {"malicious": 2, "undetected": 30},
          "last_analysis_results": {"huge": "x" * 10000},
      },
      "context_attributes": {
          "rule_name": "ExampleRule", "match_in_subfile": match_in_subfile,
      },
  }


@pytest.mark.asyncio
async def test_list_preserves_opaque_cursor_and_filters(api, ctx):
  cursor = "previous +/= opaque cursor"
  next_cursor = "next?+/= opaque cursor"
  api.get_json_async.return_value = {
      "data": [job()], "meta": {"cursor": next_cursor, "count": 71},
      "links": {"next": "https://www.virustotal.com/api/v3/next"},
  }
  result = await retrohunt.list_retrohunt_jobs(ctx, limit=2, cursor=cursor, status="finished")
  api.get_json_async.assert_awaited_once_with(
      "/intelligence/retrohunt_jobs",
      params={"limit": 2, "cursor": cursor, "filter": "status:finished"})
  assert result["returned_count"] == 1
  assert result["total_count"] == 71
  assert result["next_cursor"] == next_cursor
  assert result["has_more"] is True
  assert "rules" not in result["jobs"][0]["attributes"]
  assert result["jobs"][0]["rules_sha256"] == hashlib.sha256(RULES.encode()).hexdigest()


@pytest.mark.asyncio
@pytest.mark.parametrize("in_subfile", [False, True])
async def test_matches_keep_context_and_compact_metadata(api, ctx, in_subfile):
  api.get_json_async.return_value = {"data": [matched_file(in_subfile)], "meta": {"count": 1}}
  result = await retrohunt.get_retrohunt_matches(JOB_ID, ctx, limit=1)
  api.get_json_async.assert_awaited_once_with(
      f"/intelligence/retrohunt_jobs/{JOB_ID}/matching_files", params={"limit": 1})
  item = result["files"][0]
  assert item["sha256"] == HASH
  assert item["attributes"]["size"] == 123
  assert item["context_attributes"] == {
      "rule_name": "ExampleRule", "match_in_subfile": in_subfile}
  assert "last_analysis_results" not in item["attributes"]
  assert len(item["attributes"]["names"]) == 10
  assert item["names_truncated"] is True
  assert result["returned_count"] == 1
  assert result["has_more"] is False
  assert result["next_cursor"] is None


@pytest.mark.asyncio
async def test_empty_final_page_is_a_success(api, ctx):
  api.get_json_async.return_value = {"data": [], "meta": {"count": 0}}
  result = await retrohunt.get_retrohunt_matches(JOB_ID, ctx, cursor="last-page")
  assert result == {
      "job_id": JOB_ID, "files": [], "returned_count": 0, "total_count": 0,
      "has_more": False, "next_cursor": None,
  }


@pytest.mark.asyncio
async def test_get_job_rules_are_opt_in_and_bounded(api, ctx):
  value = job()
  full_rules = RULES * 3000
  value["attributes"]["rules"] = full_rules
  api.get_json_async.return_value = {"data": value}
  summary = await retrohunt.get_retrohunt_job(JOB_ID, ctx)
  assert "rules" not in summary["attributes"]
  detailed = await retrohunt.get_retrohunt_job(JOB_ID, ctx, include_rules=True)
  assert len(detailed["attributes"]["rules"]) == 65536
  assert detailed["rules_truncated"] is True
  assert detailed["rules_bytes"] == len(full_rules.encode())
  assert detailed["rules_sha256"] == hashlib.sha256(full_rules.encode()).hexdigest()


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["list", "job", "matches"])
@pytest.mark.parametrize("code", ["ForbiddenError", "NotFoundError", "QuotaExceededError", "TooManyRequestsError"])
async def test_api_errors_are_distinct_and_redacted(api, ctx, tool, code):
  secret = "private-api-key-password"
  api.get_json_async.side_effect = vt.error.APIError(
      code, f"https://example.invalid/?x-apikey={secret}; password={secret}")
  calls = {
      "list": lambda: retrohunt.list_retrohunt_jobs(ctx),
      "job": lambda: retrohunt.get_retrohunt_job(JOB_ID, ctx),
      "matches": lambda: retrohunt.get_retrohunt_matches(JOB_ID, ctx),
  }
  with pytest.raises(ToolError) as captured:
    await calls[tool]()
  assert str(captured.value) == f"VirusTotal API error: {code}."
  assert secret not in str(captured.value)
  assert "https://" not in str(captured.value)


@pytest.mark.asyncio
async def test_unexpected_exception_is_redacted(api, ctx):
  api.get_json_async.side_effect = RuntimeError("password=private-key https://secret.invalid")
  with pytest.raises(ToolError) as captured:
    await retrohunt.list_retrohunt_jobs(ctx)
  assert "private-key" not in str(captured.value)
  assert "secret.invalid" not in str(captured.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("job_id", ["", ".", "..", "...", "a/b", "a\\b", "a?x=1", "a#x", "%2e%2e", "a b", "a\x00b", "a" * 513])
async def test_invalid_job_ids_make_no_request(api, ctx, job_id):
  with pytest.raises(ToolError, match="InvalidArgument"):
    await retrohunt.get_retrohunt_job(job_id, ctx)
  with pytest.raises(ToolError, match="InvalidArgument"):
    await retrohunt.get_retrohunt_matches(job_id, ctx)
  api.get_json_async.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [0, -1, 41, "", None, True, 1.5])
async def test_invalid_limits_make_no_request(api, ctx, limit):
  with pytest.raises(ToolError, match="InvalidArgument"):
    await retrohunt.list_retrohunt_jobs(ctx, limit=limit)
  with pytest.raises(ToolError, match="InvalidArgument"):
    await retrohunt.get_retrohunt_matches(JOB_ID, ctx, limit=limit)
  api.get_json_async.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("cursor", ["", 1, "a" * 8193])
async def test_invalid_cursor_make_no_request(api, ctx, cursor):
  with pytest.raises(ToolError, match="InvalidArgument"):
    await retrohunt.get_retrohunt_matches(JOB_ID, ctx, cursor=cursor)
  api.get_json_async.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["", "finished OR running", 1])
async def test_invalid_status_make_no_request(api, ctx, status):
  with pytest.raises(ToolError, match="InvalidArgument"):
    await retrohunt.list_retrohunt_jobs(ctx, status=status)
  api.get_json_async.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    {}, {"data": {}}, {"data": [None]},
    {"data": [], "links": {"next": "https://secret.invalid/?token=private"}},
    {"data": [], "meta": {"cursor": "next"}, "links": {"next": None}},
])
async def test_malformed_pages_are_not_empty_successes(api, ctx, payload):
  api.get_json_async.return_value = payload
  with pytest.raises(ToolError, match="UnexpectedResponse") as captured:
    await retrohunt.list_retrohunt_jobs(ctx)
  assert "secret.invalid" not in str(captured.value)


@pytest.mark.asyncio
async def test_error_payload_is_not_an_empty_result(api, ctx):
  api.get_json_async.return_value = {"error": {"code": "ForbiddenError", "message": "private-key"}}
  with pytest.raises(ToolError, match="ForbiddenError") as captured:
    await retrohunt.get_retrohunt_matches(JOB_ID, ctx)
  assert "private-key" not in str(captured.value)
