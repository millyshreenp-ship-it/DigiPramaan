from fastapi import APIRouter, Depends
from app.trust.rbac import require_permission
from app.trust import sandbox

router = APIRouter()

@router.post("/api/cases/{case_id}/sandbox")
def create_sandbox_endpoint(case_id: str, user: dict = Depends(require_permission("sandbox:run"))):
    sbx_id = sandbox.create_sandbox(case_id, user)
    return {"sandbox_id": sbx_id}

@router.post("/api/sandbox/{sandbox_id}/inject")
def inject_sandbox_endpoint(sandbox_id: str, payload: dict, user: dict = Depends(require_permission("sandbox:run"))):
    template = payload.get("template", "Custom JSON")
    params = payload.get("params", {})
    expected = payload.get("expected_detection_type", "Unknown")
    inj_id = sandbox.inject_artifact(sandbox_id, template, params, expected, user)
    return {"injection_id": inj_id}

@router.post("/api/sandbox/{sandbox_id}/run")
def run_sandbox_endpoint(sandbox_id: str, user: dict = Depends(require_permission("sandbox:run"))):
    res = sandbox.run_sandbox(sandbox_id, user)
    return res

@router.delete("/api/sandbox/{sandbox_id}")
def destroy_sandbox_endpoint(sandbox_id: str, user: dict = Depends(require_permission("sandbox:run"))):
    return sandbox.destroy_sandbox(sandbox_id, user)
