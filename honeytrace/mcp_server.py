"""HONEYTRACE MCP server — exposes scan as an MCP tool for Cognis.Studio."""
from cognis_core.mcp import build_mcp_server
from honeytrace.core import scan, TOOL_NAME

run_mcp_server = build_mcp_server(
    tool_name=TOOL_NAME,
    description="Active-decoy network lure system — SSH, RDP, SMB, web honeypots",
    scan_fn=scan,
)

if __name__ == "__main__":
    run_mcp_server()
