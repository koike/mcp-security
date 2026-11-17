# SPDX-License-Identifier: Apache-2.0
"""新しい Python プロセスで初回起動時の警告を検出する。"""

import json
from pathlib import Path
import subprocess
import sys
import textwrap


def test_first_import_has_no_lifespan_or_syntax_warning(tmp_path):
    package_root = Path(__file__).resolve().parents[1]
    cache_dir = tmp_path / "first-import-pycache"
    assert not cache_dir.exists()

    script = textwrap.dedent(r"""
        import asyncio
        import importlib
        import json
        from pathlib import Path
        import sys
        import warnings
        from unittest.mock import patch

        warnings.filterwarnings(
            "error",
            message=r"Field 'lifespan' has an incomplete definition",
            category=Warning,
        )
        sys.path.insert(0, sys.argv[1])
        assert "gti_mcp.server" not in sys.modules

        import vt

        with patch.object(
            vt.Client, "__init__",
            side_effect=AssertionError("起動確認で VT クライアントは生成しません。"),
        ) as client_init:
            module = importlib.import_module("gti_mcp.server")
            assert Path(module.__file__).resolve() == (
                Path(sys.argv[1]) / "gti_mcp" / "server.py"
            )
            listed = asyncio.run(module.server.list_tools())
            names = {tool.name for tool in listed}
            removed = {
                "analyse_file", "create_collection",
                "update_collection_attributes", "update_iocs_in_collection",
            }
            assert len(listed) == len(names) == 39
            assert names.isdisjoint(removed)
            client_init.assert_not_called()

        print(json.dumps({"tool_count": len(names), "removed_tools": sorted(names & removed)}))
    """)

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-X", f"pycache_prefix={cache_dir}",
            "-W", "error::SyntaxWarning",
            "-c", script, str(package_root),
        ],
        cwd=tmp_path,
        env={},
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {"tool_count": 39, "removed_tools": []}
