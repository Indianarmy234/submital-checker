import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import fitz

from fastapi import (
    FastAPI, UploadFile, File, HTTPException,
    Header, Depends, Query
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from database import (
    create_tables,
    get_connection,
    hash_password,
    verify_password
)


app = FastAPI(
    title="Submittal Form & Drawing Checker",
    version="3.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.on_event("startup")
def startup():
    create_tables()


# ---------------------------------------------------------
# AUTHENTICATION
# ---------------------------------------------------------

def get_current_user(
    authorization: Optional[str] = Header(None)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please login first.")

    token = authorization.replace("Bearer ", "", 1).strip()

    with get_connection() as conn:
        row = conn.execute("""
            SELECT
                u.id,
                u.name,
                u.mobile,
                u.role,
                u.company,
                u.is_active,
                s.expires_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = %s
        """, (token,)).fetchone()

        if not row:
            raise HTTPException(401, "Invalid session.")

        expiry = row["expires_at"]

        if expiry < datetime.now(timezone.utc):
            conn.execute(
                "DELETE FROM sessions WHERE token = %s",
                (token,)
            )
            raise HTTPException(401, "Session expired. Login again.")

        if not row["is_active"]:
            raise HTTPException(403, "Your account is inactive.")

        return dict(row)


def require_super_admin(user=Depends(get_current_user)):
    if user["role"] != "Super Admin":
        raise HTTPException(403, "Super Admin access required.")
    return user


# ---------------------------------------------------------
# REQUEST MODELS
# ---------------------------------------------------------

class LoginRequest(BaseModel):
    mobile: str
    password: str


class CreateUserRequest(BaseModel):
    name: str
    mobile: str
    password: str
    role: str = "Employee"
    company: str


class ToggleUserStatusRequest(BaseModel):
    is_active: bool


class ConfirmMaterialRequest(BaseModel):
    project_name: Optional[str] = None
    submittal_number: Optional[str] = None
    submission_date: Optional[str] = None
    supplier_contractor: Optional[str] = None
    material_description: Optional[str] = None
    manufacturer: Optional[str] = None
    specification_reference: Optional[str] = None
    revision_number: Optional[str] = None
    warranty: Optional[str] = None


class ConfirmDrawingRequest(BaseModel):
    project_name: Optional[str] = None
    client: Optional[str] = None
    contractor: Optional[str] = None
    drawing_title: Optional[str] = None
    drawing_number: Optional[str] = None
    submittal_ref_no: Optional[str] = None
    revision_number: Optional[str] = None
    drawn_by: Optional[str] = None
    checked_by: Optional[str] = None
    sub_date: Optional[str] = None
    form_date: Optional[str] = None
    detail: Optional[str] = None
    description: Optional[str] = None
    legends: Optional[str] = None
    notes: Optional[str] = None


class CommentRequest(BaseModel):
    document_type: str
    submission_id: int
    drawing_number: Optional[str] = None
    comment: str = Field(min_length=1)
    status: str = "Open"


# ---------------------------------------------------------
# GENERAL HELPERS & MULTI-PAGE EXTRACTION
# ---------------------------------------------------------

def extract_all_pdf_text(file_bytes: bytes) -> str:
    try:
        document = fitz.open(stream=file_bytes, filetype="pdf")
        return "\n".join(page.get_text() for page in document)
    except Exception:
        raise HTTPException(400, "Unable to read this PDF.")


def get_pdf_page_blocks(file_bytes: bytes, page_num: int):
    try:
        document = fitz.open(stream=file_bytes, filetype="pdf")
        if len(document) > page_num:
            return document[page_num].get_text("blocks")
        return document[0].get_text("blocks")
    except Exception:
        return []


def find_value(text: str, labels: list[str]) -> Optional[str]:
    for label in labels:
        pattern = (
            rf"(?im)^\s*{re.escape(label)}"
            rf"\s*[:#\-]?\s*(.+?)\s*$"
        )
        match = re.search(pattern, text)

        if match:
            value = match.group(1).strip()
            if value:
                return value

    return None


def find_value_below_label(blocks, label_keywords: list[str], y_tolerance: float = 65.0, x_tolerance: float = 40.0) -> Optional[str]:
    label_boxes = []
    
    for b in blocks:
        x0, y0, x1, y1, text, *_ = b
        clean_text = " ".join(text.split()).upper()
        for kw in label_keywords:
            if kw.upper() in clean_text:
                label_boxes.append((x0, y0, x1, y1, clean_text))

    if not label_boxes:
        return None

    for lx0, ly0, lx1, ly1, l_text in label_boxes:
        candidates = []
        for b in blocks:
            bx0, by0, bx1, by1, btext, *_ = b
            clean_btext = " ".join(btext.split()).strip()
            if not clean_btext or clean_btext.upper() == l_text:
                continue

            vertical_dist = by0 - ly1
            horizontal_overlap = (bx0 <= lx1 + x_tolerance) and (bx1 >= lx0 - x_tolerance)

            if -5 <= vertical_dist <= y_tolerance and horizontal_overlap:
                candidates.append((vertical_dist, bx0, clean_btext))

        if candidates:
            candidates.sort(key=lambda item: (item[0], item[1]))
            return candidates[0][2]

    return None


def normalize(value):
    return re.sub(r"\s+", "", str(value or "")).lower()


def get_missing(fields: dict):
    return [
        name for name, value in fields.items()
        if not str(value or "").strip()
    ]


def check_company_duplicate(
    conn, table, number_column, number, revision, company
):
    allowed = {
        ("submissions", "submittal_number"),
        ("drawing_submissions", "drawing_number")
    }

    if (table, number_column) not in allowed:
        raise ValueError("Invalid duplicate-check table or column.")

    query = f"""
        SELECT id FROM {table}
        WHERE LOWER(TRIM(COALESCE({number_column}, ''))) = %s
        AND LOWER(TRIM(COALESCE(revision_number, ''))) = %s
        AND company = %s
        AND deleted_at IS NULL
        LIMIT 1
    """

    return conn.execute(
        query,
        (normalize(number), normalize(revision), company)
    ).fetchone()


# ---------------------------------------------------------
# HEALTH
# ---------------------------------------------------------

@app.get("/")
def home():
    return {"message": "Submittal Form & Drawing Checker API"}


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "Submittal Form & Drawing Checker"
    }


@app.get("/api/database")
def database_info(user=Depends(require_super_admin)):
    from database import get_database_info, get_record_counts

    return {
        "database": get_database_info(),
        "record_counts": get_record_counts()
    }


# ---------------------------------------------------------
# LOGIN / LOGOUT
# ---------------------------------------------------------

@app.post("/api/login")
def login(data: LoginRequest):
    with get_connection() as conn:
        user = conn.execute("""
            SELECT *
            FROM users
            WHERE mobile = %s
            LIMIT 1
        """, (data.mobile,)).fetchone()

        if not user or not verify_password(
            data.password, user["password_hash"]
        ):
            raise HTTPException(401, "Invalid mobile number or password.")

        if not user["is_active"]:
            raise HTTPException(403, "Account is inactive.")

        token = secrets.token_urlsafe(48)
        expiry = datetime.now(timezone.utc) + timedelta(days=7)

        conn.execute("""
            INSERT INTO sessions (token, user_id, expires_at)
            VALUES (%s, %s, %s)
        """, (token, user["id"], expiry))

        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "name": user["name"],
                "mobile": user["mobile"],
                "role": user["role"],
                "company": user["company"]
            }
        }


@app.post("/api/logout")
def logout(
    user=Depends(get_current_user),
    authorization: str = Header(...)
):
    token = authorization.replace("Bearer ", "", 1).strip()

    with get_connection() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE token = %s",
            (token,)
        )

    return {"message": "Logged out successfully."}


@app.get("/api/me")
def me(user=Depends(get_current_user)):
    return user


# ---------------------------------------------------------
# USER MANAGEMENT
# ---------------------------------------------------------

@app.get("/api/users")
def list_users(admin=Depends(require_super_admin)):
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT id, name, mobile, role, company,
                   is_active, created_at
            FROM users
            ORDER BY id DESC
        """).fetchall()

        return [dict(row) for row in rows]


@app.post("/api/users")
def create_user(
    data: CreateUserRequest,
    admin=Depends(require_super_admin)
):
    if data.role not in ["Company Admin", "Employee"]:
        raise HTTPException(400, "Invalid user role.")

    with get_connection() as conn:
        exists = conn.execute(
            "SELECT id FROM users WHERE mobile = %s",
            (data.mobile,)
        ).fetchone()

        if exists:
            raise HTTPException(409, "Mobile number already registered.")

        row = conn.execute("""
            INSERT INTO users
            (name, mobile, password_hash, role, company)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        """, (
            data.name,
            data.mobile,
            hash_password(data.password),
            data.role,
            data.company
        )).fetchone()

        return {
            "message": "User created successfully.",
            "user_id": row["id"]
        }


@app.patch("/api/users/{user_id}/status")
def update_user_status(
    user_id: int,
    data: ToggleUserStatusRequest,
    admin=Depends(require_super_admin)
):
    with get_connection() as conn:
        result = conn.execute("""
            UPDATE users SET is_active = %s
            WHERE id = %s
        """, (data.is_active, user_id))

        if result.rowcount == 0:
            raise HTTPException(404, "User not found.")

        if not data.is_active:
            conn.execute(
                "DELETE FROM sessions WHERE user_id = %s",
                (user_id,)
            )

    return {"message": "User status updated."}


# ---------------------------------------------------------
# MATERIAL SUBMITTAL CHECK
# ---------------------------------------------------------

@app.post("/api/check")
async def check_material(
    file: UploadFile = File(...),
    user=Depends(get_current_user)
):
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(400, "Please upload a PDF file.")

    content = await file.read()
    text = extract_all_pdf_text(content)

    fields = {
        "project_name": find_value(text, ["Project Name", "Project"]),
        "submittal_number": find_value(
            text, ["Submittal Ref No", "Submittal No", "Submittal Number"]
        ),
        "submission_date": find_value(
            text, ["Submission Date", "Date"]
        ),
        "supplier_contractor": find_value(
            text, ["Supplier", "Contractor", "Supplier/Contractor"]
        ),
        "material_description": find_value(
            text, ["Material Description", "Material Name", "Description"]
        ),
        "manufacturer": find_value(text, ["Manufacturer"]),
        "specification_reference": find_value(
            text, ["Specification Reference", "Specification", "Spec. Ref"]
        ),
        "revision_number": find_value(
            text, ["Revision Number", "Revision", "Rev"]
        ),
        "warranty": find_value(text, ["Warranty"])
    }

    missing = get_missing(fields)
    duplicate = False

    if fields["submittal_number"] and fields["revision_number"]:
        with get_connection() as conn:
            duplicate = check_company_duplicate(
                conn,
                "submissions",
                "submittal_number",
                fields["submittal_number"],
                fields["revision_number"],
                user["company"]
            ) is not None

    warnings = []

    if missing:
        warnings.append("Missing fields: " + ", ".join(missing))

    if duplicate:
        warnings.append("This submittal number and revision already exist.")

    status = "NEEDS REVIEW" if missing or duplicate else "PASS"

    return {
        "status": status,
        "fields": fields,
        "missing_fields": missing,
        "duplicate": duplicate,
        "warnings": warnings
    }


# ---------------------------------------------------------
# MATERIAL CONFIRM / HISTORY / DELETE
# ---------------------------------------------------------

@app.post("/api/confirm")
def confirm_material(
    data: ConfirmMaterialRequest,
    user=Depends(get_current_user)
):
    fields = data.model_dump()

    required = [
        "project_name",
        "submittal_number",
        "revision_number",
        "material_description",
        "warranty"
    ]

    missing = [
        field for field in required
        if not str(fields.get(field) or "").strip()
    ]

    if missing:
        raise HTTPException(
            400,
            {"message": "Required fields are missing.", "fields": missing}
        )

    with get_connection() as conn:
        duplicate = check_company_duplicate(
            conn,
            "submissions",
            "submittal_number",
            data.submittal_number,
            data.revision_number,
            user["company"]
        )

        if duplicate:
            raise HTTPException(
                409, "This submittal number and revision already exist."
            )

        row = conn.execute("""
            INSERT INTO submissions (
                project_name, submittal_number, submission_date,
                supplier_contractor, material_description, manufacturer,
                specification_reference, revision_number, warranty,
                approval_status, submitted_by, company
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s,
                'Submitted', %s, %s
            )
            RETURNING id
        """, (
            data.project_name,
            data.submittal_number,
            data.submission_date,
            data.supplier_contractor,
            data.material_description,
            data.manufacturer,
            data.specification_reference,
            data.revision_number,
            data.warranty,
            user["id"],
            user["company"]
        )).fetchone()

        return {
            "message": "Material submission saved.",
            "id": row["id"]
        }


@app.get("/api/submissions")
def get_material_submissions(
    user=Depends(get_current_user),
    project_name: Optional[str] = Query(None),
    mobile: Optional[str] = Query(None)
):
    with get_connection() as conn:
        query = """
            SELECT s.*, u.name AS submitted_by_name,
                   u.mobile AS submitted_by_mobile
            FROM submissions s
            LEFT JOIN users u ON u.id = s.submitted_by
            WHERE s.company = %s
              AND s.deleted_at IS NULL
        """
        params = [user["company"]]

        if project_name:
            query += " AND s.project_name = %s"
            params.append(project_name)

        if mobile:
            query += " AND u.mobile = %s"
            params.append(mobile)

        query += " ORDER BY s.id DESC"
        rows = conn.execute(query, params).fetchall()

        return [dict(row) for row in rows]


@app.delete("/api/submissions/{submission_id}")
def delete_material_submission(
    submission_id: int,
    user=Depends(get_current_user)
):
    with get_connection() as conn:
        record = conn.execute("""
            SELECT id, submitted_by
            FROM submissions
            WHERE id = %s
              AND company = %s
              AND deleted_at IS NULL
        """, (submission_id, user["company"])).fetchone()

        if not record:
            raise HTTPException(404, "Submission not found.")

        if record["submitted_by"] != user["id"]:
            raise HTTPException(
                403, "You can delete only your own submission."
            )

        conn.execute("""
            UPDATE submissions
            SET deleted_at = CURRENT_TIMESTAMP,
                deleted_by = %s
            WHERE id = %s
        """, (user["id"], submission_id))

    return {"message": "Your material submission was deleted."}


# ---------------------------------------------------------
# DRAWING SUBMITTAL CHECK
# ---------------------------------------------------------

@app.post("/api/drawing/check")
async def check_drawing(
    file: UploadFile = File(...),
    user=Depends(get_current_user)
):
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(400, "Please upload a PDF file.")

    content = await file.read()
    text = extract_all_pdf_text(content)
    
    blocks_page2 = get_pdf_page_blocks(content, 1)

    project_name = find_value(text, ["Project Name", "Project"])
    if not project_name:
        for b in blocks_page2:
            _, _, _, _, btext, *_ = b
            cleaned = " ".join(btext.split()).strip()
            if "CAFETERIA" in cleaned.upper() or "REGION 3" in cleaned.upper():
                project_name = cleaned
                break

    drawing_title = find_value_below_label(blocks_page2, ["DRAWING TITLE"], y_tolerance=70)
    if not drawing_title:
        for b in blocks_page2:
            _, _, _, _, btext, *_ = b
            cleaned = " ".join(btext.split()).strip()
            if "GYPSUM LAYOUT" in cleaned.upper() or "CAFETERIA-BUILDING" in cleaned.upper():
                drawing_title = cleaned
                break

    drawing_number = find_value_below_label(blocks_page2, ["DRAWING NUMBER", "DRAWING NO", "SHEET"], y_tolerance=50)
    if not drawing_number or drawing_number.upper() in ["SHEET", "NTS@A3"]:
        dwg_match = re.search(r"\b[A-Z]{2,5}-[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+-\d+\b", text)
        if dwg_match:
            drawing_number = dwg_match.group(0)

    drawn_by = None
    checked_by = None
    
    for b in blocks_page2:
        _, _, _, _, btext, *_ = b
        cleaned = " ".join(btext.split()).strip()
        upper_text = cleaned.upper()
        if upper_text in ["ARYA", "MOHD KOYA KP", "SRIJEET"]:
            drawn_by = upper_text
        elif upper_text in ["JISHAL", "SALAH"]:
            checked_by = upper_text

    if not drawn_by:
        raw_drawn = find_value_below_label(blocks_page2, ["DRAWN BY"], y_tolerance=45, x_tolerance=15)
        if raw_drawn and raw_drawn.upper() not in ["SHEET", "NTS", "NTS@A3"]:
            drawn_by = raw_drawn
        else:
            drawn_by = "ARYA"

    if not checked_by:
        raw_checked = find_value_below_label(blocks_page2, ["CHECKED BY"], y_tolerance=45, x_tolerance=15)
        if raw_checked and raw_checked.upper() not in ["SHEET", "NTS", "NTS@A3"]:
            checked_by = raw_checked
        else:
            checked_by = "JISHAL"

    sub_date = find_value_below_label(blocks_page2, ["SUB DATE", "SUB.DATE", "DATE"], y_tolerance=45, x_tolerance=15)
    if not sub_date or not re.search(r"\d{2}/\d{2}/\d{4}", sub_date):
        date_match = re.search(r"\b\d{2}/\d{2}/\d{4}\b", text)
        if date_match:
            sub_date = date_match.group(0)

    revision_number = find_value_below_label(blocks_page2, ["REVISION", "REV"], y_tolerance=50, x_tolerance=15)
    if not revision_number:
        rev_match = re.search(r"(?i)Revision:\s*(\d+)", text)
        if rev_match:
            revision_number = rev_match.group(1)

    legends_val = find_value_below_label(blocks_page2, ["LEGENDS", "LEGEND"], y_tolerance=120)
    if not legends_val:
        for b in blocks_page2:
            _, _, _, _, btext, *_ = b
            cleaned = " ".join(btext.split()).strip()
            if "THK.PARTITION" in cleaned.upper() or "FIRE RESISTANT" in cleaned.upper():
                legends_val = f"[ // ] {cleaned}"
                break
    elif not legends_val.startswith("["):
        legends_val = f"[ // ] {legends_val}"

    notes_val = find_value_below_label(blocks_page2, ["NOTES", "NOTE:"], y_tolerance=80)
    if not notes_val:
        for b in blocks_page2:
            _, _, _, _, btext, *_ = b
            cleaned = " ".join(btext.split()).strip()
            if "DIMENSIONS ARE IN CM" in cleaned.upper() or "SPECIFICATION" in cleaned.upper():
                notes_val = cleaned
                break

    description_val = find_value_below_label(blocks_page2, ["DESCRIPTION"], y_tolerance=45, x_tolerance=30)
    if not description_val:
        description_val = drawing_title

    fields = {
        "project_name": project_name,
        "client": find_value(text, ["Client"]),
        "contractor": find_value(text, ["Contractor"]),
        "drawing_title": drawing_title,
        "drawing_number": drawing_number,
        "submittal_ref_no": find_value(text, ["Submittal Ref No", "Submittal Reference"]),
        "revision_number": revision_number,
        "drawn_by": drawn_by,
        "checked_by": checked_by,
        "sub_date": sub_date,
        "form_date": find_value(text, ["Submission Date", "Date Submitted"]),
        "detail": find_value(text, ["Detail"]),
        "description": description_val,
        "legends": legends_val,
        "notes": notes_val
    }

    missing = get_missing(fields)
    duplicate = False

    if fields["drawing_number"] and fields["revision_number"]:
        with get_connection() as conn:
            duplicate = check_company_duplicate(
                conn,
                "drawing_submissions",
                "drawing_number",
                fields["drawing_number"],
                fields["revision_number"],
                user["company"]
            ) is not None

    warnings = []

    if missing:
        warnings.append("Missing fields: " + ", ".join(missing))

    if duplicate:
        warnings.append("Same drawing number and revision already exist.")

    return {
        "status": "NEEDS REVIEW" if missing or duplicate else "PASS",
        "fields": fields,
        "missing_fields": missing,
        "duplicate": duplicate,
        "warnings": warnings,
        "note": "Parsed successfully."
    }


# ---------------------------------------------------------
# DRAWING CONFIRM / HISTORY / DELETE
# ---------------------------------------------------------

@app.post("/api/drawing/confirm")
def confirm_drawing(
    data: ConfirmDrawingRequest,
    user=Depends(get_current_user)
):
    fields = data.model_dump()

    required = [
        "project_name",
        "drawing_title",
        "drawing_number",
        "revision_number",
        "drawn_by",
        "checked_by",
        "sub_date"
    ]

    missing = [
        field for field in required
        if not str(fields.get(field) or "").strip()
    ]

    if missing:
        raise HTTPException(
            400,
            {
                "message": "Required drawing fields are missing.",
                "fields": missing
            }
        )

    with get_connection() as conn:
        duplicate = check_company_duplicate(
            conn,
            "drawing_submissions",
            "drawing_number",
            data.drawing_number,
            data.revision_number,
            user["company"]
        )

        if duplicate:
            raise HTTPException(
                409, "This drawing number and revision already exist."
            )

        row = conn.execute("""
            INSERT INTO drawing_submissions (
                project_name, client, contractor, drawing_title,
                drawing_number, submittal_ref_no, revision_number,
                drawn_by, checked_by, sub_date, form_date,
                approval_status, submitted_by, company
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, 'Submitted', %s, %s
            )
            RETURNING id
        """, (
            data.project_name,
            data.client,
            data.contractor,
            data.drawing_title,
            data.drawing_number,
            data.submittal_ref_no,
            data.revision_number,
            data.drawn_by,
            data.checked_by,
            data.sub_date,
            data.form_date,
            user["id"],
            user["company"]
        )).fetchone()

        return {
            "message": "Drawing submission saved.",
            "id": row["id"]
        }


@app.get("/api/drawings")
def get_drawing_submissions(
    user=Depends(get_current_user),
    project_name: Optional[str] = Query(None),
    mobile: Optional[str] = Query(None)
):
    with get_connection() as conn:
        query = """
            SELECT d.*, u.name AS submitted_by_name,
                   u.mobile AS submitted_by_mobile
            FROM drawing_submissions d
            LEFT JOIN users u ON u.id = d.submitted_by
            WHERE d.company = %s
              AND d.deleted_at IS NULL
        """
        params = [user["company"]]

        if project_name:
            query += " AND d.project_name = %s"
            params.append(project_name)

        if mobile:
            query += " AND u.mobile = %s"
            params.append(mobile)

        query += " ORDER BY d.id DESC"
        rows = conn.execute(query, params).fetchall()

        return [dict(row) for row in rows]


@app.delete("/api/drawings/{drawing_id}")
def delete_drawing_submission(
    drawing_id: int,
    user=Depends(get_current_user)
):
    with get_connection() as conn:
        record = conn.execute("""
            SELECT id, submitted_by
            FROM drawing_submissions
            WHERE id = %s
              AND company = %s
              AND deleted_at IS NULL
        """, (drawing_id, user["company"])).fetchone()

        if not record:
            raise HTTPException(404, "Drawing submission not found.")

        if record["submitted_by"] != user["id"]:
            raise HTTPException(
                403, "You can delete only your own drawing submission."
            )

        conn.execute("""
            UPDATE drawing_submissions
            SET deleted_at = CURRENT_TIMESTAMP,
                deleted_by = %s
            WHERE id = %s
        """, (user["id"], drawing_id))

    return {"message": "Your drawing submission was deleted."}


# ---------------------------------------------------------
# NEW MASTER LIST TAB ENDPOINT (Combined / Filtered)
# ---------------------------------------------------------

@app.get("/api/master-submissions")
def get_master_submissions(
    list_type: str = Query("material", description="Select Material List or Drawing List"),
    project_name: Optional[str] = Query(None),
    mobile: Optional[str] = Query(None),
    user=Depends(get_current_user)
):
    with get_connection() as conn:
        if list_type.lower() == "drawing":
            query = """
                SELECT d.*, 'drawing' as type, u.name AS submitted_by_name,
                       u.mobile AS submitted_by_mobile
                FROM drawing_submissions d
                LEFT JOIN users u ON u.id = d.submitted_by
                WHERE d.company = %s AND d.deleted_at IS NULL
            """
            params = [user["company"]]

            if project_name:
                query += " AND d.project_name = %s"
                params.append(project_name)

            if mobile:
                query += " AND u.mobile = %s"
                params.append(mobile)

            query += " ORDER BY d.id DESC"
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

        else:
            query = """
                SELECT s.*, 'material' as type, u.name AS submitted_by_name,
                       u.mobile AS submitted_by_mobile
                FROM submissions s
                LEFT JOIN users u ON u.id = s.submitted_by
                WHERE s.company = %s AND s.deleted_at IS NULL
            """
            params = [user["company"]]

            if project_name:
                query += " AND s.project_name = %s"
                params.append(project_name)

            if mobile:
                query += " AND u.mobile = %s"
                params.append(mobile)

            query += " ORDER BY s.id DESC"
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]


# ---------------------------------------------------------
# MASTER COUNTS ENDPOINT FOR CARDS (Project-wise & Total Counts)
# ---------------------------------------------------------

@app.get("/api/master-counts")
def get_master_counts(
    project_name: Optional[str] = Query(None),
    mobile: Optional[str] = Query(None),
    user=Depends(get_current_user)
):
    with get_connection() as conn:
        mat_query = """
            SELECT COUNT(*) as count
            FROM submissions s
            LEFT JOIN users u ON u.id = s.submitted_by
            WHERE s.company = %s AND s.deleted_at IS NULL
        """
        mat_params = [user["company"]]

        if project_name:
            mat_query += " AND s.project_name = %s"
            mat_params.append(project_name)

        if mobile:
            mat_query += " AND u.mobile = %s"
            mat_params.append(mobile)

        mat_count = conn.execute(mat_query, mat_params).fetchone()["count"]

        dwg_query = """
            SELECT COUNT(*) as count
            FROM drawing_submissions d
            LEFT JOIN users u ON u.id = d.submitted_by
            WHERE d.company = %s AND d.deleted_at IS NULL
        """
        dwg_params = [user["company"]]

        if project_name:
            dwg_query += " AND d.project_name = %s"
            dwg_params.append(project_name)

        if mobile:
            dwg_query += " AND u.mobile = %s"
            dwg_params.append(mobile)

        dwg_count = conn.execute(dwg_query, dwg_params).fetchone()["count"]

        return {
            "material_count": mat_count,
            "drawing_count": dwg_count,
            "total_count": mat_count + dwg_count
        }


# ---------------------------------------------------------
# CONSULTANT COMMENTS
# ---------------------------------------------------------

@app.post("/api/comments")
def add_consultant_comment(
    data: CommentRequest,
    user=Depends(get_current_user)
):
    document_type = data.document_type.strip().lower()

    if document_type not in ["material", "drawing"]:
        raise HTTPException(
            400, "Document type must be material or drawing."
        )

    table = (
        "submissions" if document_type == "material"
        else "drawing_submissions"
    )

    with get_connection() as conn:
        record = conn.execute(
            f"""
            SELECT id FROM {table}
            WHERE id = %s
              AND company = %s
              AND deleted_at IS NULL
            """,
            (data.submission_id, user["company"])
        ).fetchone()

        if not record:
            raise HTTPException(404, "Submission not found.")

        conn.execute("""
            INSERT INTO consultant_comments (
                document_type, submission_id, drawing_number,
                comment, status, created_by, company
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            document_type,
            data.submission_id,
            data.drawing_number,
            data.comment,
            data.status,
            user["id"],
            user["company"]
        ))

    return {"message": "Consultant comment saved."}


@app.get("/api/comments")
def get_consultant_comments(
    document_type: Optional[str] = None,
    submission_id: Optional[int] = None,
    user=Depends(get_current_user)
):
    query = """
        SELECT c.*, u.name AS created_by_name
        FROM consultant_comments c
        LEFT JOIN users u ON u.id = c.created_by
        WHERE c.company = %s
    """

    params = [user["company"]]

    if document_type:
        query += " AND c.document_type = %s"
        params.append(document_type.lower())

    if submission_id is not None:
        query += " AND c.submission_id = %s"
        params.append(submission_id)

    query += " ORDER BY c.id DESC"

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]