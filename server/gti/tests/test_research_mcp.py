# SPDX-License-Identifier: Apache-2.0
"""Exercise the research workflow through the MCP protocol and a local VT stub."""

import pytest
import vt
from mcp.shared.memory import create_connected_server_and_client_session

from gti_mcp.server import server


pytestmark = pytest.mark.asyncio(loop_scope="session")
HASH = "a" * 64
JOB = "researcher-1700000000"
ZIP = "4939392292"
PASSWORD = "integration-test-password"
URL = "https://samples.example.test/archive?Signature=abc%2Fdef%3D"
ADDED = {
    "list_retrohunt_jobs", "get_retrohunt_job", "get_retrohunt_matches",
    "get_file_download_url", "create_sample_zip", "get_sample_zip_status",
    "get_sample_zip_download_url",
}


@pytest.fixture(autouse=True)
def reset_httpserver(make_httpserver_ipv4, monkeypatch):
    # Production creates a client per request; the upstream fixture shares one.
    # A shared client cannot serve a second request after vt_client closes it.
    host = f"http://{make_httpserver_ipv4.host}:{make_httpserver_ipv4.port}"
    monkeypatch.setattr(
        "gti_mcp.server.vt_client_factory",
        lambda _ctx: vt.Client("dummy_api_key", host=host, timeout=10),
    )
    make_httpserver_ipv4.clear()
    yield
    make_httpserver_ipv4.check_assertions()
    make_httpserver_ipv4.clear()


def expect(httpserver, path, payload, *, method="GET", body=None, query=None, status=200):
    options = {"method": method, "headers": {"X-Apikey": "dummy_api_key"}}
    if body is not None:
        options["json"] = body
    if query is not None:
        options["query_string"] = query
    httpserver.expect_request("/api/v3" + path, **options).respond_with_json(payload, status=status)


def zip_status(status, ok=0, errors=0):
    return {"data": {"id": ZIP, "type": "zip_file", "attributes": {
        "status": status, "progress": 100 if status == "finished" else 0,
        "files_ok": ok, "files_error": errors,
    }}}


async def call(client, name, arguments):
    result = await client.call_tool(name, arguments=arguments)
    assert not result.isError, result.content
    assert isinstance(result.structuredContent, dict)
    return result.structuredContent


async def test_retrohunt_to_zip_url_over_mcp(make_httpserver_ipv4):
    http = make_httpserver_ipv4
    job = {"id": JOB, "type": "retrohunt_job", "attributes": {
        "status": "finished", "num_matches": 1, "rules": "rule sample { condition: true }",
    }}
    expect(http, "/intelligence/retrohunt_jobs", {"data": [job]},
           query={"limit": "1", "filter": "status:finished"})
    expect(http, f"/intelligence/retrohunt_jobs/{JOB}", {"data": job})
    expect(http, f"/intelligence/retrohunt_jobs/{JOB}/matching_files", {
        "data": [{"id": HASH, "type": "file", "attributes": {"size": 12},
                  "context_attributes": {"rule_name": "sample", "match_in_subfile": False}}],
        "meta": {"count": 1},
    }, query={"limit": "1"})
    expect(http, "/intelligence/zip_files", zip_status("starting"), method="POST",
           body={"data": {"hashes": [HASH], "password": PASSWORD}})
    expect(http, f"/intelligence/zip_files/{ZIP}", zip_status("creating"))

    async with create_connected_server_and_client_session(server._mcp_server) as client:
        jobs = await call(client, "list_retrohunt_jobs", {"limit": 1, "status": "finished", "cursor": None})
        assert jobs["jobs"][0]["id"] == JOB
        detail = await call(client, "get_retrohunt_job", {"job_id": JOB})
        assert detail["attributes"]["status"] == "finished"
        matches = await call(client, "get_retrohunt_matches", {"job_id": JOB, "limit": 1, "cursor": None})
        assert matches["files"][0]["context_attributes"]["rule_name"] == "sample"
        selected_hash = matches["files"][0]["sha256"]
        created = await call(client, "create_sample_zip", {"hashes": [selected_hash], "password": PASSWORD})
        assert created["zip_password"] == PASSWORD
        assert created["zip_id"] == ZIP
        progress = await call(client, "get_sample_zip_status", {"zip_id": created["zip_id"]})
        assert progress["ready"] is False
        assert len(http.log) == 5
        http.check_assertions()
        http.clear()
        expect(http, f"/intelligence/zip_files/{ZIP}", zip_status("finished", ok=1))
        expect(http, f"/intelligence/zip_files/{ZIP}/download_url", {"data": URL})
        ready = await call(client, "get_sample_zip_download_url", {"zip_id": created["zip_id"]})
        assert ready["download_url"] == URL
        assert ready["ready"] is True
        assert ready["files_error"] == 0
        assert "dummy_api_key" not in str(ready)
        assert len(http.log) == 2


async def test_raw_url_and_error_envelope_over_mcp(make_httpserver_ipv4):
    http = make_httpserver_ipv4
    expect(http, f"/files/{HASH}/download_url", {"data": URL})
    async with create_connected_server_and_client_session(server._mcp_server) as client:
        payload = await call(client, "get_file_download_url", {"sha256": HASH})
        assert payload["download_url"] == URL
        assert len(http.log) == 1
        http.check_assertions()
        http.clear()
        expect(http, f"/files/{HASH}/download_url", {
            "error": {"code": "ForbiddenError", "message": "secret-must-not-appear"}
        }, status=403)
        error = await client.call_tool("get_file_download_url", arguments={"sha256": HASH})
        assert error.isError is True
        assert "ForbiddenError" in str(error.content)
        assert "secret-must-not-appear" not in str(error)
        assert len(http.log) == 1


async def test_new_tools_publish_schemas_without_credentials(make_httpserver_ipv4):
    async with create_connected_server_and_client_session(server._mcp_server) as client:
        result = await client.list_tools()
    tools = {item.name: item for item in result.tools}
    assert ADDED | {"search_iocs"} <= tools.keys()
    for name in ADDED:
        tool = tools[name]
        assert tool.outputSchema is not None
        assert "ctx" not in tool.inputSchema["properties"]
        assert "api_key" not in tool.inputSchema["properties"]
        assert tool.annotations.destructiveHint is False
    for name in ("list_retrohunt_jobs", "get_retrohunt_matches"):
        limit = tools[name].inputSchema["properties"]["limit"]
        assert limit["minimum"] == 1 and limit["maximum"] == 40
    assert make_httpserver_ipv4.log == []
