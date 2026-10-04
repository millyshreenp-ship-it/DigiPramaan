import re
import os
import subprocess
from app.main import app

def test_static_ui_consistency():
    with open("static/trust.js", "r", encoding="utf-8") as f:
        js = f.read()
    with open("static/index.html", "r", encoding="utf-8") as f:
        html = f.read()
        
    # (d) trust.js tag after registerTab, and initTrustTabs invoked
    assert "window.registerTab" in html
    assert "initTrustTabs" in js
    assert "initTrustTabs(window.registerTab)" in js
    
    # (a) URLs passed to api() or fetch
    from fastapi.testclient import TestClient
    TestClient(app) # Forces route flattening
    def get_paths(routes):
        paths = []
        for r in routes:
            if hasattr(r, "path"):
                paths.append(r.path)
            elif hasattr(r, "routes"):
                paths.extend(get_paths(r.routes))
            elif hasattr(r, "original_router") and hasattr(r.original_router, "routes"):
                paths.extend(get_paths(r.original_router.routes))
        return paths
    routes = get_paths(app.routes)
    
    # Extract complete URLs (including those with variables in template literals)
    # This is an approximation for static analysis.
    raw_urls = []
    
    # Matches api("/api/cases") or api('/api/cases')
    raw_urls.extend(re.findall(r'api\([\'"](/api/[^\'"]+)[\'"]\)', js))
    # Matches fetch("/api/cases") 
    raw_urls.extend(re.findall(r'fetch\([\'"](/api/[^\'"]+)[\'"]\)', js))
    
    # Matches template literals: api(`/api/cases/${caseId}/members`) -> we convert to /api/cases/{caseId}/members
    templates = re.findall(r'api\(`(/api/[^`]+)`\)', js)
    for t in templates:
        t_normalized = re.sub(r'\$\{[^}]+\}', 'VAR', t)
        raw_urls.append(t_normalized)
        
    # Matches string concatenation: api("/api/cases/" + id + "/members")
    concats = re.findall(r'api\("(/api/[^"]+)"\s*\+\s*[^+]+\s*\+\s*"([^"]+)"\)', js)
    for prefix, suffix in concats:
        raw_urls.append(prefix + "VAR" + suffix)

    # Some are just prefixes without suffix: api("/api/cases/" + encodeURIComponent(caseId))
    concats_prefix_only = re.findall(r'api\("(/api/[^"]+)"\s*\+\s*[^+]+\)', js)
    for prefix in concats_prefix_only:
        # Avoid duplicate matching with the one above
        if not any(prefix in c[0] for c in concats):
            raw_urls.append(prefix + "VAR")
            
    # And location.href = "/api/cases/" + caseId + "/certificate"
    raw_urls.extend(re.findall(r'href\s*=\s*[\'"](/api/[^\'"]+)[\'"]\s*\+\s*[^+]+\s*\+\s*[\'"]([^"]+)[\'"]', js))
    
    print("Checked URLs:", raw_urls)
    
    for u in raw_urls:
        u_base = u.split("?")[0].rstrip("/")
        # We replace VAR with a generic placeholder for matching
        u_base = u_base.replace("VAR", "REPLACEME")
        
        matched = False
        for r in routes:
            # Convert /api/cases/{case_id}/members to regex
            pattern = re.sub(r'\{[^}]+\}', 'REPLACEME', r)
            if pattern == u_base:
                matched = True
                break
        assert matched, f"URL {u} (normalized to {u_base}) in trust.js does not match any backend route"
        
    # (b) Element IDs used via $("#...")
    ids_used = re.findall(r'\$\("(#\w+)"\)', js)
    for i in ids_used:
        id_name = i[1:]
        # Must be in html or js strings
        assert f'id="{id_name}"' in html or f"id='{id_name}'" in html or f'id="{id_name}"' in js or f"id='{id_name}'" in js, f"ID {id_name} missing"
        
    # (c) inline onclick functions
    onclicks = re.findall(r'onclick="([a-zA-Z0-9_]+)\(', js)
    for oc in onclicks:
        assert f"window.{oc} =" in js or f"function {oc}" in js or f"const {oc} =" in js, f"Function {oc} missing"
        
    # (e) node --check
    try:
        subprocess.check_call(["node", "--check", "static/trust.js"])
    except FileNotFoundError:
        pass
