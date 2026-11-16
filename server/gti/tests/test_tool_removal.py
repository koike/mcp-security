# SPDX-License-Identifier: Apache-2.0
"""投稿に関係するツールの削除と、残す調査機能を MCP 経由で確認する。"""

from unittest.mock import Mock

import pytest
import vt
from mcp.shared.memory import create_connected_server_and_client_session

from gti_mcp.server import server


pytestmark = pytest.mark.asyncio(loop_scope="session")

EXPECTED_TOOLS = {
    "create_sample_zip",
    "get_collection_feature_matches",
    "get_collection_mitre_tree",
    "get_collection_report",
    "get_collection_rules",
    "get_collection_timeline_events",
    "get_collections_commonalities",
    "get_domain_report",
    "get_entities_related_to_a_collection",
    "get_entities_related_to_a_domain",
    "get_entities_related_to_a_file",
    "get_entities_related_to_a_hunting_ruleset",
    "get_entities_related_to_an_ip_address",
    "get_entities_related_to_an_url",
    "get_file_behavior_report",
    "get_file_behavior_summary",
    "get_file_download_url",
    "get_file_report",
    "get_hunting_ruleset",
    "get_ip_address_report",
    "get_retrohunt_job",
    "get_retrohunt_matches",
    "get_sample_zip_download_url",
    "get_sample_zip_status",
    "get_threat_profile",
    "get_threat_profile_associations_timeline",
    "get_threat_profile_recommendations",
    "get_url_report",
    "list_retrohunt_jobs",
    "list_threat_profiles",
    "search_campaigns",
    "search_digital_threat_monitoring",
    "search_iocs",
    "search_malware_families",
    "search_software_toolkits",
    "search_threat_actors",
    "search_threat_reports",
    "search_threats",
    "search_vulnerabilities",
}

REMOVED_TOOL_CALLS = [
    ("analyse_file", {"file_path": "/tmp/gti-removal-test-sample.bin"}),
    ("create_collection", {
        "name": "Removal test",
        "description": "Synthetic test data",
        "iocs": ["https://example.test/removal-test"],
        "private": False,
    }),
    ("update_collection_attributes", {
        "id": "test_collection",
        "attributes": {"private": False},
    }),
    ("update_iocs_in_collection", {
        "id": "test_collection",
        "relationship": "urls",
        "iocs": ["https://example.test/removal-test"],
        "operation": "add",
    }),
]


@pytest.fixture(autouse=True)
def reset_httpserver(make_httpserver_ipv4):
    make_httpserver_ipv4.clear()
    yield
    make_httpserver_ipv4.check_assertions()
    make_httpserver_ipv4.clear()


@pytest.fixture
def no_vt_client(monkeypatch):
    factory = Mock(side_effect=AssertionError("VT クライアントの生成は不要です。"))
    monkeypatch.setattr("gti_mcp.server.vt_client_factory", factory)
    return factory


@pytest.fixture
def local_vt_client(make_httpserver_ipv4, monkeypatch):
    host = f"http://{make_httpserver_ipv4.host}:{make_httpserver_ipv4.port}"
    factory = Mock(side_effect=lambda _ctx: vt.Client(
        "dummy_api_key", host=host, timeout=10))
    monkeypatch.setattr("gti_mcp.server.vt_client_factory", factory)
    return factory


async def test_mcp_lists_exactly_the_remaining_tools(no_vt_client):
    async with create_connected_server_and_client_session(server._mcp_server) as client:
        result = await client.list_tools()

    assert len(result.tools) == 39
    assert {tool.name for tool in result.tools} == EXPECTED_TOOLS
    no_vt_client.assert_not_called()


@pytest.mark.parametrize("name, arguments", REMOVED_TOOL_CALLS)
async def test_removed_tool_calls_are_unknown_without_creating_vt_client(
    no_vt_client, name, arguments,
):
    async with create_connected_server_and_client_session(server._mcp_server) as client:
        result = await client.call_tool(name, arguments=arguments)

    assert result.isError is True
    messages = [item.text for item in result.content if item.type == "text"]
    assert any(f"Unknown tool: {name}" in message for message in messages)
    no_vt_client.assert_not_called()


async def test_url_report_404_does_not_fall_back_to_submission(
    make_httpserver_ipv4, local_vt_client,
):
    httpserver = make_httpserver_ipv4
    url = "https://example.test/unknown-url"
    path = f"/api/v3/urls/{vt.url_id(url)}"
    httpserver.expect_request(
        path, method="GET", headers={"X-Apikey": "dummy_api_key"},
    ).respond_with_json(
        {"error": {"code": "NotFoundError", "message": "URL not found"}},
        status=404,
    )

    async with create_connected_server_and_client_session(server._mcp_server) as client:
        result = await client.call_tool("get_url_report", arguments={"url": url})

    assert not result.isError
    assert "NotFoundError" in result.structuredContent["result"]["error"]
    assert [(request.method, request.path) for request, _ in httpserver.log] == [
        ("GET", path),
    ]
    local_vt_client.assert_called_once()


async def test_content_search_remains_available_without_submission(
    make_httpserver_ipv4, local_vt_client,
):
    httpserver = make_httpserver_ipv4
    query = 'content:"synthetic test marker"'
    sha256 = "a" * 64
    context = {"confidence": 1.0, "match_in_subfile": False, "snippet": "test-snippet"}
    httpserver.expect_request(
        "/api/v3/intelligence/search", method="GET",
        headers={"X-Apikey": "dummy_api_key"},
        query_string={"query": query, "order": "last_submission_date-"},
    ).respond_with_json({
        "data": [{"id": sha256, "type": "file", "attributes": {"size": 123},
                  "context_attributes": context}],
    })

    async with create_connected_server_and_client_session(server._mcp_server) as client:
        result = await client.call_tool(
            "search_iocs", arguments={"query": query, "limit": 1},
        )

    assert not result.isError
    matches = result.structuredContent["result"]
    assert len(matches) == 1
    assert matches[0]["id"] == sha256
    assert matches[0]["context_attributes"] == context
    assert [(request.method, request.path) for request, _ in httpserver.log] == [
        ("GET", "/api/v3/intelligence/search"),
    ]
    local_vt_client.assert_called_once()
