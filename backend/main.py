import json
import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import List, Optional

# Database modules
from database import init_db, get_db, ThreatLog

# Intelligence service modules
from services.url_scanner import scan_url
from services.email_analyzer import analyze_email_headers
from services.ip_checker import check_ip_reputation
from services.domain_lookup import lookup_domain_info
from services.osint_scanner import scan_email_osint

# Initialize FastAPI app
app = FastAPI(
    title="Cyber Threat Analyzer API",
    description="Backend threat assessment engines for URL, Email Headers, IP addresses, and Domain intelligence.",
    version="1.0.0"
)

# Enable CORS for React development server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify front-end origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize SQLite tables on startup
@app.on_event("startup")
def startup_event():
    init_db()

# Pydantic schemas
class URLScanRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze", example="http://malicious-phish.net")

class EmailAnalyzeRequest(BaseModel):
    headers: str = Field(..., description="Raw email header block")

class IPCheckRequest(BaseModel):
    ip: str = Field(..., description="The IPv4 or IPv6 address to check", example="8.8.8.8")

class DomainLookupRequest(BaseModel):
    domain: str = Field(..., description="The domain name to check", example="google.com")

class NotesUpdateRequest(BaseModel):
    analyst_notes: str = Field(..., description="Updated investigator notes")

class OSINTCheckRequest(BaseModel):
    email: str = Field(..., description="The email address to search for credentials leaks", example="admin@corporate.gov")

# Pydantic schemas for police fields
class PoliceFields(BaseModel):
    fir_case_id: str = ""
    investigator_name: str = ""
    complaint_id: str = ""

# Helper function to save scans to database logs
def save_log(db: Session, input_val: str, scan_type: str, result_dict: dict, police_fields: PoliceFields = None):
    try:
        # Stringify JSON for SQLite storage
        result_json = json.dumps(result_dict)
        db_log = ThreatLog(
            input_value=input_val,
            scan_type=scan_type,
            result=result_json,
            analyst_notes="",
            fir_case_id=police_fields.fir_case_id if police_fields else "",
            investigator_name=police_fields.investigator_name if police_fields else "",
            complaint_id=police_fields.complaint_id if police_fields else ""
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        return db_log
    except Exception as e:
        print(f"Error saving log to db: {e}")
        return None

# Endpoints
@app.get("/")
def read_root():
    return {"status": "online", "service": "Cyber Threat Analyzer", "version": "1.0.0"}

class URLScanRequestWithPolice(BaseModel):
    url: str = Field(..., description="The URL to analyze", example="http://malicious-phish.net")
    police: PoliceFields = PoliceFields()

class EmailAnalyzeRequestWithPolice(BaseModel):
    headers: str = Field(..., description="Raw email header block")
    police: PoliceFields = PoliceFields()

class IPCheckRequestWithPolice(BaseModel):
    ip: str = Field(..., description="The IPv4 or IPv6 address to check", example="8.8.8.8")
    police: PoliceFields = PoliceFields()

class DomainLookupRequestWithPolice(BaseModel):
    domain: str = Field(..., description="The domain name to check", example="google.com")
    police: PoliceFields = PoliceFields()

class OSINTCheckRequestWithPolice(BaseModel):
    email: str = Field(..., description="The email address to search for credentials leaks", example="admin@corporate.gov")
    police: PoliceFields = PoliceFields()

@app.post("/api/scan-url")
def api_scan_url(payload: URLScanRequestWithPolice, db: Session = Depends(get_db)):
    result = scan_url(payload.url)
    if not result.get("success", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=result.get("error", "Failed to scan URL")
        )
    save_log(db, payload.url, "URL", result, payload.police)
    return result

@app.post("/api/analyze-email")
def api_analyze_email(payload: EmailAnalyzeRequestWithPolice, db: Session = Depends(get_db)):
    result = analyze_email_headers(payload.headers)
    if not result.get("success", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=result.get("error", "Failed to analyze headers")
        )
    # Store first 100 characters of headers as display input
    display_input = f"From: {result['headers'].get('from', 'Unknown')} | Subj: {result['headers'].get('subject', 'No Subject')}"
    save_log(db, display_input, "EMAIL", result, payload.police)
    return result

@app.post("/api/check-ip")
def api_check_ip(payload: IPCheckRequestWithPolice, db: Session = Depends(get_db)):
    result = check_ip_reputation(payload.ip)
    if not result.get("success", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=result.get("error", "Failed to analyze IP")
        )
    save_log(db, payload.ip, "IP", result, payload.police)
    return result

@app.post("/api/domain-info")
def api_domain_info(payload: DomainLookupRequestWithPolice, db: Session = Depends(get_db)):
    result = lookup_domain_info(payload.domain)
    if not result.get("success", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=result.get("error", "Failed to resolve domain")
        )
    save_log(db, payload.domain, "DOMAIN", result, payload.police)
    return result

@app.post("/api/check-osint")
def api_check_osint(payload: OSINTCheckRequestWithPolice, db: Session = Depends(get_db)):
    result = scan_email_osint(payload.email)
    if not result.get("success", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=result.get("error", "Failed to scan email leaks")
        )
    save_log(db, payload.email, "OSINT", result, payload.police)
    return result

@app.get("/api/logs")
def get_logs(db: Session = Depends(get_db)):
    try:
        logs = db.query(ThreatLog).order_by(ThreatLog.timestamp.desc()).all()
        # Parse stored JSON result back to dictionary
        formatted_logs = []
        for log in logs:
            try:
                parsed_result = json.loads(log.result)
            except Exception:
                parsed_result = {"raw": log.result}
            
            formatted_logs.append({
                "id": log.id,
                "input_value": log.input_value,
                "scan_type": log.scan_type,
                "result": parsed_result,
                "timestamp": log.timestamp.isoformat(),
                "analyst_notes": log.analyst_notes,
                "fir_case_id": log.fir_case_id,
                "investigator_name": log.investigator_name,
                "complaint_id": log.complaint_id
            })
        return formatted_logs
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database retrieval error: {str(e)}"
        )

@app.post("/api/logs/{log_id}/notes")
def update_notes(log_id: int, payload: NotesUpdateRequest, db: Session = Depends(get_db)):
    log = db.query(ThreatLog).filter(ThreatLog.id == log_id).first()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log entry not found"
        )
    try:
        log.analyst_notes = payload.analyst_notes
        db.commit()
        db.refresh(log)
        return {"success": True, "notes": log.analyst_notes}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update analyst notes: {str(e)}"
        )

@app.post("/api/logs/{log_id}/police")
def update_police_fields(log_id: int, payload: PoliceFields, db: Session = Depends(get_db)):
    log = db.query(ThreatLog).filter(ThreatLog.id == log_id).first()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log entry not found"
        )
    try:
        log.fir_case_id = payload.fir_case_id
        log.investigator_name = payload.investigator_name
        log.complaint_id = payload.complaint_id
        db.commit()
        db.refresh(log)
        return {"success": True, "fir_case_id": log.fir_case_id, "investigator_name": log.investigator_name, "complaint_id": log.complaint_id}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update police fields: {str(e)}"
        )

@app.get("/api/logs/{log_id}/pdf")
def export_log_pdf(log_id: int, db: Session = Depends(get_db)):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from io import BytesIO
    
    log = db.query(ThreatLog).filter(ThreatLog.id == log_id).first()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log entry not found"
        )
    
    try:
        result = json.loads(log.result)
    except Exception:
        result = {"raw": log.result}
    
    # Generate PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.darkblue,
        alignment=TA_CENTER,
        spaceAfter=30
    )
    elements.append(Paragraph("Amroha Police - Cyber Threat Intelligence Report", title_style))
    
    # Case Info Table
    case_data = [
        ["FIR Case ID", log.fir_case_id or "Not Provided"],
        ["Complaint ID", log.complaint_id or "Not Provided"],
        ["Investigator Name", log.investigator_name or "Not Provided"],
        ["Scan Type", log.scan_type],
        ["Input Analyzed", log.input_value],
        ["Analysis Timestamp", log.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")]
    ]
    case_table = Table(case_data, colWidths=[200, 300])
    case_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.lightblue),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.black),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
    ]))
    elements.append(case_table)
    elements.append(Spacer(1, 20))
    
    # Threat Analysis
    elements.append(Paragraph("<b>Threat Analysis Result:</b>", styles['Heading2']))
    
    # Risk Level
    risk_level = result.get('status', result.get('risk_level', 'Unknown')).capitalize()
    threat_score = result.get('threat_score', 0)
    
    risk_color = colors.green
    if "malicious" in risk_level.lower() or threat_score >= 70:
        risk_color = colors.red
    elif "suspicious" in risk_level.lower() or threat_score >= 30:
        risk_color = colors.orange
    
    risk_data = [
        ["Risk Level", Paragraph(f"<font color='{risk_color}'><b>{risk_level}</b></font>", styles['Normal'])],
        ["Threat Severity Score", f"{threat_score}/100"],
        ["Source Intelligence", result.get('mode', 'Simulation')]
    ]
    risk_table = Table(risk_data, colWidths=[200, 300])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.lightgrey),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.black),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
    ]))
    elements.append(risk_table)
    elements.append(Spacer(1, 20))
    
    # Recommended Action
    elements.append(Paragraph("<b>Recommended Action:</b>", styles['Heading2']))
    recommended_action = "No specific action - scan indicates no immediate threat."
    if threat_score >= 70:
        recommended_action = "HIGH RISK! Immediate investigation required. Block the domain/IP/URL and preserve evidence for legal proceedings."
    elif threat_score >= 30:
        recommended_action = "SUSPICIOUS! Monitor further activity and conduct additional investigation as needed."
    
    elements.append(Paragraph(recommended_action, styles['BodyText']))
    elements.append(Spacer(1, 20))
    
    # Detailed Analysis Summary
    elements.append(Paragraph("<b>Detailed Analysis Summary:</b>", styles['Heading2']))
    summary_text = f"Input analyzed: {log.input_value} | "
    if log.scan_type == "URL":
        summary_text += f"URL scanned. SSL status: {result.get('heuristics', {}).get('ssl_details', 'N/A')} | "
        summary_text += f"VirusTotal flags: {result.get('virustotal', {}).get('malicious', 0)} vendors"
    elif log.scan_type == "DOMAIN":
        summary_text += "Domain lookup performed"
    elif log.scan_type == "IP":
        summary_text += "IP reputation checked"
    elif log.scan_type == "EMAIL":
        summary_text += "Email headers analyzed"
    elif log.scan_type == "OSINT":
        summary_text += "Email OSINT scan performed"
    
    elements.append(Paragraph(summary_text, styles['BodyText']))
    elements.append(Spacer(1, 20))
    
    # Analyst Notes
    if log.analyst_notes:
        elements.append(Paragraph("<b>Investigator Notes:</b>", styles['Heading2']))
        elements.append(Paragraph(log.analyst_notes, styles['BodyText']))
    
    doc.build(elements)
    buffer.seek(0)
    
    from fastapi.responses import StreamingResponse
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=threat-report-{log_id}.pdf"}
    )

@app.delete("/api/logs/{log_id}")
def delete_log(log_id: int, db: Session = Depends(get_db)):
    log = db.query(ThreatLog).filter(ThreatLog.id == log_id).first()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log entry not found"
        )
    try:
        db.delete(log)
        db.commit()
        return {"success": True, "message": f"Log {log_id} deleted successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete log entry: {str(e)}"
        )

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    """Computes aggregate analytics for dashboard visuals."""
    try:
        logs = db.query(ThreatLog).all()
        total_scans = len(logs)
        
        url_count = 0
        email_count = 0
        ip_count = 0
        domain_count = 0
        osint_count = 0
        
        safe_count = 0
        suspicious_count = 0
        malicious_count = 0

        for log in logs:
            # Type count
            if log.scan_type == "URL":
                url_count += 1
            elif log.scan_type == "EMAIL":
                email_count += 1
            elif log.scan_type == "IP":
                ip_count += 1
            elif log.scan_type == "DOMAIN":
                domain_count += 1
            elif log.scan_type == "OSINT":
                osint_count += 1
            
            # Severity status check
            try:
                res = json.loads(log.result)
                status_val = res.get("status", res.get("risk_level", "Safe")).lower()
                if "malicious" in status_val or "high" in status_val:
                    malicious_count += 1
                elif "suspicious" in status_val or "medium" in status_val or "caution" in status_val:
                    suspicious_count += 1
                else:
                    safe_count += 1
            except Exception:
                safe_count += 1 # fallback

        # If zero logs, seed with 0
        return {
            "total_scans": total_scans,
            "by_type": {
                "URL": url_count,
                "EMAIL": email_count,
                "IP": ip_count,
                "DOMAIN": domain_count,
                "OSINT": osint_count
            },
            "by_severity": {
                "Safe": safe_count,
                "Suspicious": suspicious_count,
                "Malicious": malicious_count
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Stats generation error: {str(e)}"
        )
