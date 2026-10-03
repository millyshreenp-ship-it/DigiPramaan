import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from app.trust.rbac import require_permission, get_case_or_403
from app import config, db, custody
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics import renderPDF
from reportlab.graphics.shapes import Drawing

router = APIRouter()

@router.get("/api/cases/{case_id}/certificate")
def generate_certificate(case_id: str, user: dict = Depends(require_permission("audit:export"))):
    get_case_or_403(case_id, user)
    
    cert_dir = os.path.join(config.DATA_DIR, "certificates")
    os.makedirs(cert_dir, exist_ok=True)
    pdf_path = os.path.join(cert_dir, f"{case_id}_certificate.pdf")
    
    c = canvas.Canvas(pdf_path, pagesize=letter, pageCompression=0)
    c.drawString(100, 750, f"Section 63 Certificate (Inspired) - Case {case_id}")
    c.drawString(100, 730, "Part A: Custodian / Part B: Expert")
    
    with db.session() as conn:
        latest_anchor = conn.execute("SELECT merkle_root, key_id FROM audit_anchors ORDER BY seq_to DESC LIMIT 1").fetchone()
        evidence_list = conn.execute("SELECT filename, sha256 FROM evidence WHERE case_id = ?", (case_id,)).fetchall()
        
    merkle_root = latest_anchor["merkle_root"] if latest_anchor else "none"
    key_id = latest_anchor["key_id"] if latest_anchor else "none"

    # QR Code
    qrw = QrCodeWidget(f"{case_id}|{merkle_root}|{key_id}")
    b = qrw.getBounds()
    d = Drawing(100, 100, transform=[100/b[2],0,0,100/b[3],0,0])
    d.add(qrw)
    renderPDF.draw(d, c, 400, 650)
    
    c.drawString(100, 710, f"Latest Audit Root: {merkle_root}")
    c.drawString(100, 690, f"Signing Key ID: {key_id}")
    
    y = 650
    if user["role"] == "auditor":
        c.drawString(100, y, "Evidence List: REDACTED for auditor role")
    else:
        c.drawString(100, y, "Evidence List (SHA-256/512):")
        y -= 20
        for ev in evidence_list:
            c.drawString(100, y, f"- {ev['filename']}: {ev['sha256']}")
            y -= 15
            if y < 100:
                c.showPage()
                y = 750
    
    # TODO: Verify layout, exact required fields, and signatures against the official schedule of Bharatiya Sakshya Adhiniyam 2023
    c.drawString(100, 50, "Prototype template. Statutory wording must be validated by legal counsel.")
    c.save()
    
    with db.session() as conn:
        custody.append(conn, actor=user["username"], action="certificate_generated", case_id=case_id, detail={"path": pdf_path})
        
    return FileResponse(pdf_path, filename=f"{case_id}_certificate.pdf")
