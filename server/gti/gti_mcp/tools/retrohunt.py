# SPDX-License-Identifier: Apache-2.0
"""Read existing Retrohunt jobs and their matching files."""

import hashlib
import re
from typing import Annotated, Any

import vt
from mcp.server.fastmcp import Context
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from ..server import server, vt_client


__all__ = ["list_retrohunt_jobs", "get_retrohunt_job", "get_retrohunt_matches"]

_PAGE_LIMIT = Annotated[int, Field(strict=True, ge=1, le=40)]
_MAX_CURSOR_LENGTH = 8192
_MAX_RULES_LENGTH = 65536
_JOB_ID = re.compile(r"[A-Za-z0-9._~-]{1,512}\Z")
_STATUSES = {"starting", "running", "aborting", "aborted", "finished"}
_READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True,
    openWorldHint=True)
_SAFE_ERROR_CODES = {
    "APIError", "BadRequestError", "InvalidArgumentError", "NotFoundError",
    "AlreadyExistsError", "NotAvailableYet", "UnselectiveContentQueryError",
    "AccessDeniedError", "AuthenticationRequiredError", "WrongCredentialsError",
    "ForbiddenError", "QuotaExceededError", "TooManyRequestsError",
    "TransientError", "DeadlineExceededError", "FailedDependencyError",
    "UserNotActiveError", "ClientError", "ServerError", "UnknownError",
}
_JOB_ATTRIBUTES = (
    "status", "corpus", "creation_date", "start_date", "finish_date",
    "progress", "eta_seconds", "num_matches", "num_matches_outside_time_range",
    "scanned_bytes", "time_range",
)
_FILE_ATTRIBUTES = (
    "sha256", "sha1", "md5", "size", "meaningful_name", "type_description",
    "type_tag", "type_extension", "first_submission_date", "last_submission_date",
    "last_analysis_date", "last_analysis_stats", "downloadable", "ssdeep", "tlsh",
)


def _invalid_response() -> ToolError:
  return ToolError("UnexpectedResponse: VirusTotal returned an invalid response.")


def _validate_job_id(job_id: str) -> None:
  if (not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id)
      or not job_id.strip(".")):
    raise ToolError("InvalidArgument: job_id must be a valid Retrohunt identifier.")


def _page_params(limit: int, cursor: str | None) -> dict[str, Any]:
  if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 40:
    raise ToolError("InvalidArgument: limit must be an integer from 1 to 40.")
  params: dict[str, Any] = {"limit": limit}
  if cursor is not None:
    if (not isinstance(cursor, str) or not cursor
        or len(cursor) > _MAX_CURSOR_LENGTH):
      raise ToolError("InvalidArgument: cursor must contain 1 to 8192 characters.")
    params["cursor"] = cursor
  return params


def _api_error(code: Any) -> ToolError:
  # API messages can contain request URLs or credentials; return only known codes.
  safe_code = code if isinstance(code, str) and code in _SAFE_ERROR_CODES else "APIError"
  return ToolError(f"VirusTotal API error: {safe_code}.")


async def _get_json(
    ctx: Context, path: str, params: dict[str, Any] | None = None
) -> dict[str, Any]:
  try:
    async with vt_client(ctx) as client:
      payload = await client.get_json_async(path, params=params)
  except vt.error.APIError as error:
    raise _api_error(error.code) from None
  except Exception:
    raise ToolError("VirusTotal request failed; check connectivity and server configuration.") from None
  if not isinstance(payload, dict):
    raise _invalid_response()
  if "error" in payload:
    error = payload["error"]
    raise _api_error(error.get("code") if isinstance(error, dict) else None)
  return payload


def _page_data(
    payload: dict[str, Any], limit: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
  data = payload.get("data")
  meta = payload.get("meta", {})
  links = payload.get("links", {})
  if (not isinstance(data, list) or len(data) > limit
      or not all(isinstance(item, dict) for item in data)
      or not isinstance(meta, dict) or not isinstance(links, dict)):
    raise _invalid_response()
  next_cursor = meta.get("cursor")
  if next_cursor == "":
    next_cursor = None
  if next_cursor is not None and (
      not isinstance(next_cursor, str) or len(next_cursor) > _MAX_CURSOR_LENGTH):
    raise _invalid_response()
  next_link = links.get("next")
  if next_link is not None and not isinstance(next_link, str):
    raise _invalid_response()
  if next_link and next_cursor is None:
    raise ToolError("UnexpectedResponse: the next page has no continuation cursor.")
  if "next" in links and not next_link and next_cursor is not None:
    raise ToolError("UnexpectedResponse: pagination fields disagree.")
  page = {
      "returned_count": len(data),
      "next_cursor": next_cursor,
      "has_more": next_cursor is not None,
  }
  if "count" in meta:
    count = meta["count"]
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
      raise _invalid_response()
    page["total_count"] = count
  return data, page


def _object_attributes(item: dict[str, Any]) -> dict[str, Any]:
  if not isinstance(item.get("id"), str) or not item["id"]:
    raise _invalid_response()
  attributes = item.get("attributes", {})
  if not isinstance(attributes, dict):
    raise _invalid_response()
  return attributes


def _job_summary(item: dict[str, Any], include_rules: bool = False) -> dict[str, Any]:
  attributes = _object_attributes(item)
  result = {
      "id": item["id"],
      "type": "retrohunt_job",
      "attributes": {key: attributes[key] for key in _JOB_ATTRIBUTES if key in attributes},
  }
  rules = attributes.get("rules")
  if isinstance(rules, str):
    encoded = rules.encode("utf-8")
    result["rules_sha256"] = hashlib.sha256(encoded).hexdigest()
    result["rules_bytes"] = len(encoded)
    if include_rules:
      result["attributes"]["rules"] = rules[:_MAX_RULES_LENGTH]
      result["rules_truncated"] = len(rules) > _MAX_RULES_LENGTH
  return result


def _file_summary(item: dict[str, Any]) -> dict[str, Any]:
  attributes = _object_attributes(item)
  context = item.get("context_attributes", {})
  if not isinstance(context, dict):
    raise _invalid_response()
  selected = {key: attributes[key] for key in _FILE_ATTRIBUTES if key in attributes}
  names = attributes.get("names")
  if isinstance(names, list):
    selected["names"] = names[:10]
  sha256 = attributes.get("sha256", item["id"])
  if not isinstance(sha256, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
    raise _invalid_response()
  result = {
      "id": item["id"],
      "type": "file",
      "sha256": sha256.lower(),
      "attributes": selected,
      "context_attributes": {
          key: context[key] for key in ("rule_name", "match_in_subfile") if key in context
      },
  }
  if isinstance(names, list) and len(names) > 10:
    result["names_truncated"] = True
  return result


@server.tool(annotations=_READ_ONLY)
async def list_retrohunt_jobs(
    ctx: Context, limit: _PAGE_LIMIT = 10, cursor: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
  """List one page of existing Retrohunt jobs, without their rule bodies.

  Pass next_cursor unchanged to continue. Status may be starting, running,
  aborting, aborted, or finished. returned_count is the size of this page.
  """
  params = _page_params(limit, cursor)
  if status is not None:
    if not isinstance(status, str) or status not in _STATUSES:
      raise ToolError("InvalidArgument: status must be a supported Retrohunt status.")
    params["filter"] = f"status:{status}"
  payload = await _get_json(ctx, "/intelligence/retrohunt_jobs", params)
  data, page = _page_data(payload, limit)
  return {"jobs": [_job_summary(item) for item in data], **page}


@server.tool(annotations=_READ_ONLY)
async def get_retrohunt_job(
    job_id: str, ctx: Context, include_rules: bool = False,
) -> dict[str, Any]:
  """Get an existing Retrohunt job's status and rule hash.

  Set include_rules to return up to 65536 rule characters. rules_truncated
  marks shortened output; rules_sha256 always covers the complete rule text.
  """
  _validate_job_id(job_id)
  if not isinstance(include_rules, bool):
    raise ToolError("InvalidArgument: include_rules must be a boolean.")
  payload = await _get_json(ctx, f"/intelligence/retrohunt_jobs/{job_id}")
  data = payload.get("data")
  if not isinstance(data, dict):
    raise _invalid_response()
  return _job_summary(data, include_rules)


@server.tool(annotations=_READ_ONLY)
async def get_retrohunt_matches(
    job_id: str, ctx: Context, limit: _PAGE_LIMIT = 10,
    cursor: str | None = None,
) -> dict[str, Any]:
  """Get one page of files matched by an existing Retrohunt job.

  Returns hashes, file metadata, rule_name, and match_in_subfile. Names are
  limited to ten per file. Pass next_cursor unchanged to retrieve another page.
  """
  _validate_job_id(job_id)
  params = _page_params(limit, cursor)
  payload = await _get_json(
      ctx, f"/intelligence/retrohunt_jobs/{job_id}/matching_files", params)
  data, page = _page_data(payload, limit)
  return {"job_id": job_id, "files": [_file_summary(item) for item in data], **page}
