from scanners import SecurityScannerAgent


def test_scanner_agent_mock_returns_findings():
    results, merged = SecurityScannerAgent().run("http://localhost:5000")
    assert len(results) == 4            # trivy, nmap, nikto, zap
    assert len(merged) > 0
    assert any(f.cve_id for f in merged)
