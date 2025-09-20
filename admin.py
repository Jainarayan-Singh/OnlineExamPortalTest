import os
import mimetypes
import pandas as pd
from functools import wraps
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename
from googleapiclient.http import MediaFileUpload
from googleapiclient.errors import HttpError
import json
import pandas as pd
from flask import request, jsonify, render_template
import os, json
from flask import session, redirect, url_for, request
from markupsafe import escape
import html
from latex_editor import latex_bp
from markupsafe import Markup
from drive_utils import safe_csv_save_with_retry
from sessions import require_valid_session, generate_session_token, save_session_record, invalidate_session, get_session_by_token
from datetime import datetime



from google_drive_service import (
    create_drive_service,         
    create_subject_folder,
    load_csv_from_drive,
    save_csv_to_drive,
    clear_cache,
    find_file_by_name,
    get_drive_service_for_upload  # USER OAUTH (token.json) — for image uploads & folder ops
)
from sessions import require_valid_session

# ========== Blueprint ==========
admin_bp = Blueprint("admin", __name__, url_prefix="/admin", template_folder="templates")
admin_bp.register_blueprint(latex_bp)
# ========== Config ==========
USERS_FILE_ID     = os.environ.get("USERS_FILE_ID")
EXAMS_FILE_ID     = os.environ.get("EXAMS_FILE_ID")
QUESTIONS_FILE_ID = os.environ.get("QUESTIONS_FILE_ID")
SUBJECTS_FILE_ID  = os.environ.get("SUBJECTS_FILE_ID")
REQUESTS_RAISED_FILE_ID = os.environ.get("REQUESTS_RAISED_FILE_ID")

UPLOAD_TMP_DIR = os.path.join(os.path.dirname(__file__), "uploads_tmp")
os.makedirs(UPLOAD_TMP_DIR, exist_ok=True)

ALLOWED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
MAX_FILE_SIZE_MB = 15

# Allowed HTML tags for question text (very limited)
BLEACH_ALLOWED_TAGS = ["br", "b", "i", "u", "sup", "sub", "strong", "em"]
BLEACH_ALLOWED_ATTRIBUTES = {}  # no attributes allowed

EXAM_ATTEMPTS_FILE_ID = os.environ.get("EXAM_ATTEMPTS_FILE_ID")

# ========== Helpers ==========
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            flash("Admin login required.", "warning")
            return redirect(url_for("admin.admin_login"))
        return f(*args, **kwargs)
    return wrapper

def _get_subject_folders(service):
    """Return [{'id', 'name', 'folder_id'}] from subjects.csv for dropdown."""
    out = []
    try:
        if not SUBJECTS_FILE_ID:
            return out
        df = load_csv_from_drive(service, SUBJECTS_FILE_ID)  # caching ok
        if df is None or df.empty:
            return out
        norm = {c.lower(): c for c in df.columns}
        name_col = norm.get("subject_name") or norm.get("name")
        folder_col = norm.get("subject_folder_id") or norm.get("folder_id")
        id_col = norm.get("id")
        if not (name_col and folder_col):
            return out
        for _, r in df.iterrows():
            fid = str(r.get(folder_col, "")).strip()
            if fid:
                out.append({
                    "id": int(r.get(id_col, 0)) if (id_col and id_col in df.columns) else None,
                    "name": str(r.get(name_col, "")).strip(),
                    "folder_id": fid,
                })
    except Exception as e:
        print(f"⚠️ _get_subject_folders error: {e}")
    out.sort(key=lambda x: x["name"].lower())
    return out


def sanitize_for_display(text):
    if not text:
        return ""
    # HTML escape sab kuch
    safe = html.escape(str(text))
    # But allow <br> and mathjax ($$...$$)
    safe = safe.replace("&lt;br&gt;", "<br>")
    safe = safe.replace("&lt;br/&gt;", "<br>")
    safe = safe.replace("&dollar;&dollar;", "$$")
    return safe


def sanitize_html(s):
    """
    Lightweight sanitizer used by admin listing.
    - Normalizes newlines (CRLF -> LF)
    - Escapes HTML special chars to prevent injection
    - Returns a plain string (safe for template rendering without |safe)
    """
    if s is None:
        return ""
    s = str(s)
    # normalize newlines
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    # escape HTML special chars
    return str(escape(s))


@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        identifier = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "").strip()
        from main import load_csv_with_cache
        users_df = load_csv_with_cache("users.csv")
        if users_df.empty:
            flash("No users available!", "error")
            return redirect(url_for("admin.admin_login"))

        users_df["username_lower"] = users_df["username"].astype(str).str.strip().str.lower()
        users_df["email_lower"] = users_df["email"].astype(str).str.strip().str.lower()
        users_df["role_lower"] = users_df["role"].astype(str).str.strip().str.lower()

        user_row = users_df[
            (users_df["username_lower"] == identifier) |
            (users_df["email_lower"] == identifier)
        ]
        if user_row.empty:
            flash("Invalid username/email or password!", "error")
            return redirect(url_for("admin.admin_login"))

        user = user_row.iloc[0]
        if str(user.get("password", "")) != password:
            flash("Invalid username/email or password!", "error")
            return redirect(url_for("admin.admin_login"))

        role = str(user.get("role", "")).lower()
        if "admin" not in role:
            flash("You do not have admin access.", "error")
            return redirect(url_for("admin.admin_login"))

        # enforce single active session for this user (invalidate previous tokens)
        try:
            invalidate_session(int(user["id"]))
        except Exception as e:
            print("[admin_login] invalidate_session error:", e)

        # create new token and save server-side record
        # create new token and save locally (fast)
        token = generate_session_token()
        save_session_record({
            "user_id": int(user["id"]),
            "token": token,
            "device_info": request.headers.get("User-Agent", "unknown"),
            "is_exam_active": False
        })

        # set flask session for admin
        session["admin_id"] = int(user["id"])
        session["admin_name"] = user.get("username")
        session["user_id"] = int(user["id"])
        session["username"] = user.get("username")
        session["full_name"] = user.get("full_name", user.get("username"))
        session["token"] = token
        session.permanent = True
        print("[admin_login] flask session snapshot:", {k: session.get(k) for k in ['user_id','token','admin_id','admin_name']})

        flash("Admin login successful!", "success")
        return redirect(url_for("admin.dashboard"))

    return render_template("admin/admin_login.html")

def _parse_max_attempts(raw):
    if raw is None:
        return None
    s = str(raw).strip()
    if s == "":
        return None
    if not s.isdigit():
        raise ValueError("max_attempts must be a non-negative integer")
    val = int(s)
    if val < 0:
        raise ValueError("max_attempts must be non-negative")
    return val

@admin_bp.route("/logout")
def logout():
    """Enhanced admin logout - completely clear session and invalidate tokens"""
    uid = session.get("user_id")
    tok = session.get("token")
    
    # Invalidate server-side session
    if uid and tok:
        try:
            from sessions import invalidate_session, set_exam_active
            set_exam_active(uid, tok, is_active=False)
            invalidate_session(uid, token=tok)
        except Exception as e:
            print(f"[admin_logout] Error invalidating session: {e}")
    
    # Completely clear Flask session
    session.clear()
    
    flash("Admin logout successful.", "success")
    return redirect(url_for("home"))

# ========== Dashboard ==========
@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    sa = create_drive_service()

    exams_df = load_csv_from_drive(sa, EXAMS_FILE_ID)
    users_df = load_csv_from_drive(sa, USERS_FILE_ID)

    total_exams = 0 if exams_df is None or exams_df.empty else len(exams_df)
    total_users = 0 if users_df is None or users_df.empty else len(users_df)

    admins_count = 0
    if users_df is not None and not users_df.empty and "role" in users_df.columns:
        admins_count = (
            users_df["role"]
            .astype(str)
            .str.strip()
            .str.lower()
            .str.contains("admin")
            .sum()
        )

    stats = {
        "total_exams": total_exams,
        "total_users": total_users,
        "total_admins": admins_count,
    }
    return render_template("admin/dashboard.html", stats=stats)

# ========== Subjects ==========
@admin_bp.route("/subjects", methods=["GET", "POST"])
@admin_required
def subjects():
    sa = create_drive_service()
    subjects_df = load_csv_from_drive(sa, SUBJECTS_FILE_ID)

    if request.method == "POST":
        subject_name = request.form["subject_name"].strip()
        if not subject_name:
            flash("Subject name required.", "danger")
            return redirect(url_for("admin.subjects"))

        if (not subjects_df.empty and
            subjects_df["subject_name"].astype(str).str.lower().eq(subject_name.lower()).any()):
            flash("Subject already exists.", "warning")
            return redirect(url_for("admin.subjects"))

        try:
            drive_owner = get_drive_service_for_upload()
        except Exception as e:
            flash(f"Cannot create folder: {e}", "danger")
            return redirect(url_for("admin.subjects"))

        folder_id, created_at = create_subject_folder(drive_owner, subject_name)

        new_id = 1 if subjects_df.empty else int(subjects_df["id"].max()) + 1
        new_row = pd.DataFrame([{
            "id": new_id,
            "subject_name": subject_name,
            "subject_folder_id": folder_id,
            "subject_folder_created_at": created_at
        }])
        updated_df = pd.concat([subjects_df, new_row], ignore_index=True)
        safe_csv_save_with_retry(updated_df, 'subjects')
        clear_cache()
        flash(f"Subject '{subject_name}' created successfully.", "success")
        return redirect(url_for("admin.subjects"))

    return render_template("admin/subjects.html", subjects=subjects_df.to_dict(orient="records"))

@admin_bp.route("/subjects/edit/<int:subject_id>", methods=["POST"])
@admin_required
def edit_subject(subject_id):
    sa = create_drive_service()
    subjects_df = load_csv_from_drive(sa, SUBJECTS_FILE_ID)
    if subjects_df.empty or subject_id not in subjects_df["id"].values:
        flash("Subject not found.", "danger")
        return redirect(url_for("admin.subjects"))

    new_name = request.form.get("subject_name", "").strip()
    if not new_name:
        flash("Subject name required.", "danger")
        return redirect(url_for("admin.subjects"))

    row = subjects_df[subjects_df["id"] == subject_id].iloc[0]
    folder_id = row["subject_folder_id"]

    try:
        drive_owner = get_drive_service_for_upload()
        drive_owner.files().update(fileId=folder_id, body={"name": new_name}).execute()
    except Exception as e:
        print(f"⚠️ rename folder failed: {e}")
        flash("Drive folder rename failed; CSV updated.", "warning")

    subjects_df.loc[subjects_df["id"] == subject_id, "subject_name"] = new_name
    safe_csv_save_with_retry(subjects_df, 'subjects')
    clear_cache()
    flash("Subject updated successfully.", "success")
    return redirect(url_for("admin.subjects"))

@admin_bp.route("/subjects/delete/<int:subject_id>")
@admin_required
def delete_subject(subject_id):
    service = create_drive_service()
    subjects_df = load_csv_from_drive(service, SUBJECTS_FILE_ID)
    if subjects_df is None or subjects_df.empty:
        flash("No subjects found.", "warning")
        return redirect(url_for("admin.subjects"))

    if "id" not in subjects_df.columns:
        flash("Subjects file is missing 'id' column.", "danger")
        return redirect(url_for("admin.subjects"))
    working_df = subjects_df.copy()
    working_df["id"] = pd.to_numeric(working_df["id"], errors="coerce").astype("Int64")

    hit = working_df[working_df["id"] == int(subject_id)]
    if hit.empty:
        flash("Subject not found.", "danger")
        return redirect(url_for("admin.subjects"))

    folder_id_col = "subject_folder_id" if "subject_folder_id" in working_df.columns else "folder_id"
    folder_id = str(hit.iloc[0].get(folder_id_col, "")).strip()

    if folder_id:
        try:
            drive_owner = get_drive_service_for_upload()
            try:
                drive_owner.files().delete(fileId=folder_id, supportsAllDrives=True).execute()
                print(f"✅ Deleted folder {folder_id} using owner OAuth client.")
            except Exception as e_del:
                print(f"⚠ Owner delete failed for {folder_id}: {e_del} — trying to trash it instead.")
                try:
                    drive_owner.files().update(fileId=folder_id, body={"trashed": True}, supportsAllDrives=True).execute()
                    print(f"♻ Trashed folder {folder_id} using owner OAuth client.")
                except Exception as e_trash:
                    print(f"❌ Failed to trash folder {folder_id} with owner client: {e_trash}")
        except Exception as e_owner:
            print(f"⚠ get_drive_service_for_upload() failed: {e_owner}. Trying service-account client as fallback.")
            try:
                service.files().delete(fileId=folder_id, supportsAllDrives=True).execute()
                print(f"✅ Deleted folder {folder_id} using service-account client (fallback).")
            except Exception as e_sa:
                print(f"❌ Fallback SA delete also failed for {folder_id}: {e_sa}")

    new_df = working_df[working_df["id"] != int(subject_id)].copy()
    ok = safe_csv_save_with_retry(new_df, 'subjects')
    if ok:
        clear_cache()
        flash("Subject deleted (Drive folder removed if permitted).", "info")
    else:
        flash("Failed to update subjects.csv after delete.", "danger")

    return redirect(url_for("admin.subjects"))

# ========== Exams ==========
@admin_bp.route("/exams", methods=["GET", "POST"])
@admin_required
def exams():
    service = create_drive_service()
    exams_df = load_csv_from_drive(service, EXAMS_FILE_ID)
    if exams_df is None:
        exams_df = pd.DataFrame()
    if "max_attempts" not in exams_df.columns:
        exams_df["max_attempts"] = ""
    if request.method == "POST":
        form = request.form
        try:
            new_id = int(exams_df["id"].max()) + 1 if not exams_df.empty else 1
        except Exception:
            new_id = 1
        try:
            parsed_max = _parse_max_attempts(form.get("max_attempts", ""))
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("admin.exams"))
        row = {
            "id": new_id,
            "name": form.get("name", "").strip(),
            "date": form.get("date", "").strip(),
            "start_time": form.get("start_time", "").strip(),
            "duration": int(form.get("duration") or 0),
            "total_questions": int(form.get("total_questions") or 0),
            "status": form.get("status", "").strip(),
            "instructions": form.get("instructions", "").strip(),
            "positive_marks": form.get("positive_marks", "").strip(),
            "negative_marks": form.get("negative_marks", "").strip(),
            "max_attempts": "" if parsed_max is None else str(parsed_max)
        }
        new_df = pd.concat([exams_df, pd.DataFrame([row])], ignore_index=True)
        ok = safe_csv_save_with_retry(new_df, 'exams')
        if ok:
            clear_cache()
            flash("Exam created successfully.", "success")
            return redirect(url_for("admin.exams"))
        else:
            flash("Failed to save exam.", "danger")
            return redirect(url_for("admin.exams"))
    return render_template("admin/exams.html", exams=exams_df.to_dict(orient="records"))


@admin_bp.route("/exams/edit/<int:exam_id>", methods=["GET", "POST"])
@admin_required
def edit_exam(exam_id):
    service = create_drive_service()
    exams_df = load_csv_from_drive(service, EXAMS_FILE_ID)
    if exams_df is None:
        exams_df = pd.DataFrame()
    if "max_attempts" not in exams_df.columns:
        exams_df["max_attempts"] = ""
    exam = exams_df[exams_df["id"] == exam_id]
    if exam.empty:
        flash("Exam not found.", "danger")
        return redirect(url_for("admin.exams"))
    if request.method == "POST":
        form = request.form
        try:
            duration_val = int(form.get("duration") or 0)
            total_q_val = int(form.get("total_questions") or 0)
        except Exception:
            flash("Duration and Total Questions must be integers.", "danger")
            return redirect(url_for("admin.edit_exam", exam_id=exam_id))
        try:
            parsed_max = _parse_max_attempts(form.get("max_attempts", ""))
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("admin.edit_exam", exam_id=exam_id))
        exams_df.loc[exams_df["id"] == exam_id, [
            "name", "date", "start_time", "duration",
            "total_questions", "status",
            "instructions", "positive_marks", "negative_marks", "max_attempts"
        ]] = [
            form.get("name", "").strip(),
            form.get("date", "").strip(),
            form.get("start_time", "").strip(),
            duration_val,
            total_q_val,
            form.get("status", "").strip(),
            form.get("instructions", "").strip(),
            form.get("positive_marks", "").strip(),
            form.get("negative_marks", "").strip(),
            "" if parsed_max is None else str(parsed_max)
        ]
        ok = safe_csv_save_with_retry(exams_df, 'exams')
        if ok:
            clear_cache()
            flash("Exam updated successfully.", "success")
            return redirect(url_for("admin.exams"))
        else:
            flash("Failed to save exam changes.", "danger")
            return redirect(url_for("admin.edit_exam", exam_id=exam_id))
    return render_template("admin/edit_exam.html", exam=exam.iloc[0].to_dict())

@admin_bp.route("/exams/delete/<int:exam_id>", methods=["GET"])
@admin_required
def delete_exam(exam_id):
    service = create_drive_service()
    exams_df = load_csv_from_drive(service, EXAMS_FILE_ID)
    if exams_df is None or exams_df.empty:
        flash("Exam not found.", "danger")
        return redirect(url_for("admin.exams"))
    try:
        ids = exams_df["id"].astype(int)
    except Exception:
        ids = exams_df["id"].apply(lambda x: int(str(x).strip()) if str(x).strip().isdigit() else None)
    if int(exam_id) not in ids.tolist():
        flash("Exam not found.", "danger")
        return redirect(url_for("admin.exams"))
    exams_df = exams_df[ids != int(exam_id)].reset_index(drop=True)
    ok = safe_csv_save_with_retry(exams_df, "exams")
    if ok:
        clear_cache()
        flash("Exam deleted successfully.", "success")
    else:
        flash("Failed to delete exam.", "danger")
    return redirect(url_for("admin.exams"))

# ========== Questions helpers & CRUD ==========
QUESTIONS_COLUMNS = [
    "id", "exam_id", "question_text", "option_a", "option_b", "option_c", "option_d",
    "correct_answer", "question_type", "image_path", "positive_marks", "negative_marks", "tolerance"
]

def _ensure_questions_df(df):
    """Return a DataFrame guaranteed to have QUESTIONS_COLUMNS in order and safe dtypes."""
    if df is None or df.empty:
        df = pd.DataFrame(columns=QUESTIONS_COLUMNS)

    for c in QUESTIONS_COLUMNS:
        if c not in df.columns:
            df[c] = ""

    for col in ("positive_marks", "negative_marks", "tolerance"):
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str)

    return df[QUESTIONS_COLUMNS].copy()

@admin_bp.route("/questions", methods=["GET"])
@admin_required
def questions_index():
    sa = create_drive_service()
    exams_df = load_csv_from_drive(sa, EXAMS_FILE_ID)
    exams = []
    if not exams_df.empty:
        for _, r in exams_df.iterrows():
            exams.append({
                "id": int(r.get("id")) if "id" in exams_df.columns and str(r.get("id")).strip() else None,
                "name": r.get("name") if "name" in exams_df.columns else f"Exam {r.get('id')}"
            })

    selected_exam_id = request.args.get("exam_id", type=int)
    if not selected_exam_id and exams:
        selected_exam_id = exams[0]["id"]

    questions_df = load_csv_from_drive(sa, QUESTIONS_FILE_ID)
    questions_df = _ensure_questions_df(questions_df)

    if selected_exam_id:
        filtered = questions_df[questions_df["exam_id"].astype(str) == str(selected_exam_id)]
    else:
        filtered = questions_df.copy()

    questions = []
    for _, r in filtered.iterrows():
        # sanitize server-side and keep markup safe for templates
        qtext = sanitize_html(r.get("question_text", ""))
        questions.append({
            "id": int(r["id"]) if str(r["id"]).strip() else None,
            "exam_id": int(r["exam_id"]) if str(r["exam_id"]).strip() else None,
            "question_text": qtext,
            "option_a": sanitize_html(r.get("option_a", "")),
            "option_b": sanitize_html(r.get("option_b", "")),
            "option_c": sanitize_html(r.get("option_c", "")),
            "option_d": sanitize_html(r.get("option_d", "")),
            "correct_answer": r.get("correct_answer", ""),
            "question_type": r.get("question_type", ""),
            "image_path": r.get("image_path", ""),
            "positive_marks": r.get("positive_marks", ""),
            "negative_marks": r.get("negative_marks", ""),
            "tolerance": r.get("tolerance", "")
        })

    return render_template("admin/questions.html",
                           exams=exams,
                           selected_exam_id=selected_exam_id,
                           questions=questions)

@admin_bp.route("/questions/add", methods=["GET", "POST"])
@admin_required
def add_question():
    sa = create_drive_service()
    exams_df = load_csv_from_drive(sa, EXAMS_FILE_ID)
    exams = []
    if not exams_df.empty:
        for _, r in exams_df.iterrows():
            exams.append({"id": int(r.get("id")) if "id" in exams_df.columns and str(r.get("id")).strip() else None,
                          "name": r.get("name") if "name" in exams_df.columns else f"Exam {r.get('id')}"})

    if request.method == "POST":
        qdf = load_csv_from_drive(sa, QUESTIONS_FILE_ID)
        qdf = _ensure_questions_df(qdf)

        try:
            next_id = int(qdf["id"].max()) + 1 if not qdf.empty and qdf["id"].astype(str).str.strip().any() else 1
        except Exception:
            next_id = 1

        data = request.form.to_dict()
        new_row = {
            "id": next_id,
            "exam_id": int(data.get("exam_id") or 0),
            "question_text": data.get("question_text", "").strip(),
            "option_a": data.get("option_a", "").strip(),
            "option_b": data.get("option_b", "").strip(),
            "option_c": data.get("option_c", "").strip(),
            "option_d": data.get("option_d", "").strip(),
            "correct_answer": data.get("correct_answer", "").strip(),
            "question_type": data.get("question_type", "").strip(),
            "image_path": data.get("image_path", "").strip(),
            "positive_marks": data.get("positive_marks", "").strip() or "4",
            "negative_marks": data.get("negative_marks", "").strip() or "1",
            "tolerance": data.get("tolerance", "").strip() or ""
        }

        new_df = pd.concat([qdf, pd.DataFrame([new_row])], ignore_index=True)
        ok = safe_csv_save_with_retry(new_df, 'questions')
        if ok:
            clear_cache()
            flash("Question added successfully.", "success")
            return redirect(url_for("admin.questions_index", exam_id=new_row["exam_id"]))
        else:
            flash("Failed to save question.", "danger")
            return redirect(url_for("admin.add_question"))

    return render_template("admin/add_question.html", exams=exams, question=None, form_mode="add")

@admin_bp.route("/questions/edit/<int:question_id>", methods=["GET", "POST"])
@admin_required
def edit_question(question_id):
    sa = create_drive_service()
    exams_df = load_csv_from_drive(sa, EXAMS_FILE_ID)
    exams = []
    if not exams_df.empty:
        for _, r in exams_df.iterrows():
            exams.append({"id": int(r.get("id")) if "id" in exams_df.columns and str(r.get("id")).strip() else None,
                          "name": r.get("name") if "name" in exams_df.columns else f"Exam {r.get('id')}"})

    qdf = load_csv_from_drive(sa, QUESTIONS_FILE_ID)
    qdf = _ensure_questions_df(qdf)

    hit = qdf[qdf["id"].astype(str) == str(question_id)]
    if hit.empty:
        flash("Question not found.", "danger")
        return redirect(url_for("admin.questions_index"))

    if request.method == "POST":
        data = request.form.to_dict()
        idx = hit.index[0]
        qdf.at[idx, "exam_id"] = int(data.get("exam_id") or qdf.at[idx, "exam_id"])
        qdf.at[idx, "question_text"] = data.get("question_text", "").strip()
        qdf.at[idx, "option_a"] = data.get("option_a", "").strip()
        qdf.at[idx, "option_b"] = data.get("option_b", "").strip()
        qdf.at[idx, "option_c"] = data.get("option_c", "").strip()
        qdf.at[idx, "option_d"] = data.get("option_d", "").strip()
        qdf.at[idx, "correct_answer"] = data.get("correct_answer", "").strip()
        qdf.at[idx, "question_type"] = data.get("question_type", "").strip()
        qdf.at[idx, "image_path"] = data.get("image_path", "").strip()
        qdf.at[idx, "positive_marks"] = data.get("positive_marks", "").strip() or "4"
        qdf.at[idx, "negative_marks"] = data.get("negative_marks", "").strip() or "1"
        qdf.at[idx, "tolerance"] = data.get("tolerance", "").strip() or ""

        ok = save_csv_to_drive(sa, qdf, QUESTIONS_FILE_ID)
        if ok:
            clear_cache()
            flash("Question updated.", "success")
            return redirect(url_for("admin.questions_index", exam_id=qdf.at[idx, "exam_id"]))
        else:
            flash("Failed to save changes.", "danger")
            return redirect(url_for("admin.edit_question", question_id=question_id))

    qrow = hit.iloc[0].to_dict()
    # Provide sanitized markup to the edit form (it will be shown inside textarea - we send raw string)
    return render_template("admin/edit_question.html", exams=exams, question=qrow, form_mode="edit")

@admin_bp.route("/questions/delete/<int:question_id>", methods=["POST"])
@admin_required
def delete_question(question_id):
    sa = create_drive_service()
    qdf = load_csv_from_drive(sa, QUESTIONS_FILE_ID)
    qdf = _ensure_questions_df(qdf)
    new_df = qdf[qdf["id"].astype(str) != str(question_id)].copy()
    ok = safe_csv_save_with_retry(new_df, 'questions')
    if ok:
        clear_cache()
        flash("Question deleted.", "info")
    else:
        flash("Failed to delete question.", "danger")
    return redirect(url_for("admin.questions_index"))

@admin_bp.route("/questions/delete-multiple", methods=["POST"])
@admin_required
def delete_multiple_questions():
    try:
        payload = request.get_json(force=True)
        if not payload or "ids" not in payload:
            return jsonify({"success": False, "message": "Invalid payload"}), 400

        ids = payload.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return jsonify({"success": False, "message": "No IDs provided"}), 400

        ids_str = set([str(int(i)) for i in ids if str(i).strip()])

        sa = create_drive_service()
        qdf = load_csv_from_drive(sa, QUESTIONS_FILE_ID)
        qdf = _ensure_questions_df(qdf)

        before_count = len(qdf)
        new_df = qdf[~qdf["id"].astype(str).isin(ids_str)].copy()
        after_count = len(new_df)
        deleted_count = before_count - after_count

        ok = safe_csv_save_with_retry(new_df, 'questions')
        if not ok:
            return jsonify({"success": False, "message": "Failed to save updated questions CSV"}), 500

        clear_cache()
        return jsonify({"success": True, "deleted": deleted_count})

    except Exception as e:
        print(f"❌ delete_multiple_questions error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@admin_bp.route("/questions/bulk-update", methods=["POST"])
@admin_required
def questions_bulk_update():
    try:
        payload = request.get_json(force=True)
        if not payload:
            return jsonify({"success": False, "message": "Empty payload"}), 400

        exam_id = payload.get("exam_id")
        qtype = str(payload.get("question_type") or "").strip()
        pos = payload.get("positive_marks")
        neg = payload.get("negative_marks")
        tol = payload.get("tolerance")

        if not exam_id:
            return jsonify({"success": False, "message": "exam_id required"}), 400
        if not qtype:
            return jsonify({"success": False, "message": "question_type required"}), 400

        pos_str = None if pos is None else str(pos).strip()
        neg_str = None if neg is None else str(neg).strip()
        tol_str = None if tol is None else str(tol)

        sa = create_drive_service()
        qdf = load_csv_from_drive(sa, QUESTIONS_FILE_ID)
        qdf = _ensure_questions_df(qdf)

        mask_exam = qdf["exam_id"].astype(str) == str(exam_id)
        mask_type = qdf["question_type"].astype(str).str.strip().str.upper() == qtype.upper()
        mask = mask_exam & mask_type

        if not mask.any():
            return jsonify({"success": True, "updated": 0, "message": "No matching questions found"}), 200

        idxs = qdf[mask].index.tolist()
        for idx in idxs:
            if pos_str is not None and pos_str != "":
                qdf.at[idx, "positive_marks"] = pos_str
            if neg_str is not None and neg_str != "":
                qdf.at[idx, "negative_marks"] = neg_str
            if tol is not None:
                qdf.at[idx, "tolerance"] = tol_str

        ok = save_csv_to_drive(sa, qdf, QUESTIONS_FILE_ID)
        if not ok:
            return jsonify({"success": False, "message": "Failed to save CSV"}), 500

        clear_cache()
        return jsonify({"success": True, "updated": len(idxs)}), 200

    except Exception as e:
        print(f"❌ questions_bulk_update error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

# ========== Upload Images ==========
from googleapiclient.http import MediaIoBaseUpload  # add near other imports
import io

@admin_bp.route("/upload-images", methods=["GET", "POST"])
@admin_required
def upload_images_page():
    if request.method == "POST":
        try:
            folder_id = request.form.get("subject_folder_id", "").strip()
            files = request.files.getlist("images")

            if not folder_id:
                return jsonify({"success": False, "message": "No folder selected."}), 400
            if not files:
                return jsonify({"success": False, "message": "No files received."}), 400

            try:
                drive_upload = get_drive_service_for_upload()
            except Exception as e:
                return jsonify({"success": False, "message": str(e)}), 500

            uploaded = 0
            failed = []

            for f in files:
                if not f or not f.filename:
                    continue
                safe_name = secure_filename(f.filename)
                ext = os.path.splitext(safe_name)[1].lower()
                if ext not in ALLOWED_IMAGE_EXTS:
                    failed.append({"filename": safe_name, "error": f"Not allowed type ({ext})"})
                    continue

                f.seek(0, os.SEEK_END)
                size_mb = f.tell() / (1024 * 1024)
                f.seek(0)
                if size_mb > MAX_FILE_SIZE_MB:
                    failed.append({"filename": safe_name, "error": f"Exceeds {MAX_FILE_SIZE_MB} MB"})
                    continue

                temp_path = os.path.join(UPLOAD_TMP_DIR, safe_name)
                f.save(temp_path)

                fh = None
                try:
                    existing_id = find_file_by_name(drive_upload, safe_name, folder_id)
                    mime, _ = mimetypes.guess_type(safe_name)
                    fh = open(temp_path, "rb")
                    media = MediaIoBaseUpload(fh, mimetype=mime or "application/octet-stream", resumable=True)

                    if existing_id:
                        drive_upload.files().update(fileId=existing_id, media_body=media).execute()
                    else:
                        drive_upload.files().create(
                            body={"name": safe_name, "parents": [folder_id]},
                            media_body=media,
                            fields="id"
                        ).execute()
                    uploaded += 1
                except HttpError as e:
                    failed.append({"filename": safe_name, "error": str(e)})
                except Exception as e:
                    failed.append({"filename": safe_name, "error": str(e)})
                finally:
                    try:
                        if fh and not fh.closed:
                            fh.close()
                    except Exception as _close_err:
                        print(f"⚠ Could not close temp file handle for {temp_path}: {_close_err}")
                    try:
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                    except Exception as rm_err:
                        print(f"⚠ Could not remove temp file {temp_path}: {rm_err}")

            return jsonify({"success": True, "uploaded": uploaded, "failed": failed}), 200

        except Exception as e:
            return jsonify({"success": False, "message": f"Unexpected error: {str(e)}"}), 500

    sa = create_drive_service()
    subjects = _get_subject_folders(sa)
    load_error = None if subjects else "No subjects found (or subjects.csv missing)."
    return render_template(
        "admin/upload_images.html",
        subjects=subjects,
        load_error=load_error
    )

@admin_bp.route("/questions/batch-add", methods=["POST"])
@admin_required
def questions_batch_add():
    try:
        payload = request.get_json(force=True)
        if not payload or "questions" not in payload or "exam_id" not in payload:
            return jsonify({"success": False, "message": "Invalid payload"}), 400

        exam_id = int(payload.get("exam_id"))
        items = payload.get("questions", [])
        if not items:
            return jsonify({"success": False, "message": "No questions provided"}), 400

        sa = create_drive_service()
        qdf = load_csv_from_drive(sa, QUESTIONS_FILE_ID)
        qdf = _ensure_questions_df(qdf)

        try:
            next_id = int(qdf["id"].max()) + 1 if not qdf.empty and qdf["id"].astype(str).str.strip().any() else 1
        except Exception:
            next_id = 1

        new_rows = []
        added_count = 0
        for it in items:
            qt = (it.get("question_text") or "").strip()
            if not qt:
                continue
            row = {
                "id": next_id,
                "exam_id": exam_id,
                "question_text": qt,
                "option_a": (it.get("option_a") or "").strip(),
                "option_b": (it.get("option_b") or "").strip(),
                "option_c": (it.get("option_c") or "").strip(),
                "option_d": (it.get("option_d") or "").strip(),
                "correct_answer": (it.get("correct_answer") or "").strip(),
                "question_type": (it.get("question_type") or "MCQ").strip(),
                "image_path": (it.get("image_path") or "").strip(),
                "positive_marks": str(it.get("positive_marks") or "4"),
                "negative_marks": str(it.get("negative_marks") or "1"),
                "tolerance": str(it.get("tolerance") or "")
            }
            new_rows.append(row)
            next_id += 1
            added_count += 1

        if not new_rows:
            return jsonify({"success": False, "message": "No valid rows to add"}), 400

        appended = pd.concat([qdf, pd.DataFrame(new_rows)], ignore_index=True)
        ok = safe_csv_save_with_retry(appended, 'questions')
        if not ok:
            return jsonify({"success": False, "message": "Failed to save to Drive"}), 500

        clear_cache()
        return jsonify({"success": True, "added": added_count})

    except Exception as e:
        print(f"❌ questions_batch_add error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

# ========== Publish ==========
@admin_bp.route("/publish", methods=["GET", "POST"])
@admin_required
def publish():
    if request.method == "POST":
        clear_cache()
        try:
            from main import clear_user_cache
            clear_user_cache()
            session["force_refresh"] = True
        except Exception as e:
            print(f"⚠️ Failed to clear user cache: {e}")
        flash("✅ All caches cleared. Fresh data will load now!", "success")
        return redirect(url_for("admin.dashboard"))
    return render_template("admin/publish.html")

# --- START: Web OAuth routes for admin (paste into admin.py) ---


# Make sure your Flask app sets a secret key (main.py already may do this).
# These routes are under admin_bp (url_prefix="/admin"), so redirect URIs must include /admin/oauth2callback

@admin_bp.route("/authorize", methods=["GET"])
@admin_required
def admin_oauth_authorize():
    """
    Start web-OAuth flow (one-time). User (admin) must visit this and approve Google Drive scopes.
    Requires GOOGLE_OAUTH_CLIENT_JSON env (client_secret.json content or path).
    """
    from google_auth_oauthlib.flow import Flow

    raw = os.getenv("GOOGLE_OAUTH_CLIENT_JSON")
    if not raw:
        return "Missing GOOGLE_OAUTH_CLIENT_JSON env. Paste your client_secret_web.json here.", 500

    # Accept either raw JSON text or a file path
    try:
        cfg = json.loads(raw) if raw.strip().startswith("{") else json.load(open(raw, "r", encoding="utf-8"))
    except Exception as e:
        return f"Failed to load client JSON: {e}", 500

    # prefer 'web' key if present
    client_cfg = {"web": cfg.get("web")} if "web" in cfg else {"installed": cfg.get("installed", cfg)}
    scopes = ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/drive.file", "https://www.googleapis.com/auth/drive.readonly"]

    flow = Flow.from_client_config(client_cfg, scopes=scopes)
    # redirect URI must match EXACTLY what's in Google Cloud Console (see instructions)
    flow.redirect_uri = url_for("admin.admin_oauth_callback", _external=True)

    auth_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true", prompt="consent")
    session["oauth_state"] = state
    return redirect(auth_url)

@admin_bp.route("/oauth2callback", methods=["GET"])
@admin_required
def admin_oauth_callback():
    """
    OAuth callback for admin authorize. Exchanges code -> token and attempts to save token.json.
    If server can't write file, it will return the token JSON so you can paste it into Render env.
    """
    from google_auth_oauthlib.flow import Flow
    from google.oauth2.credentials import Credentials as UserCredentials
    from googleapiclient.discovery import build
    import datetime

    raw = os.getenv("GOOGLE_OAUTH_CLIENT_JSON")
    if not raw:
        return "Missing GOOGLE_OAUTH_CLIENT_JSON env. Cannot complete auth.", 500

    try:
        cfg = json.loads(raw) if raw.strip().startswith("{") else json.load(open(raw, "r", encoding="utf-8"))
    except Exception as e:
        return f"Failed to load client JSON: {e}", 500

    client_cfg = {"web": cfg.get("web")} if "web" in cfg else {"installed": cfg.get("installed", cfg)}
    scopes = ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/drive.file", "https://www.googleapis.com/auth/drive.readonly"]

    state = session.get("oauth_state")
    flow = Flow.from_client_config(client_cfg, scopes=scopes, state=state)
    flow.redirect_uri = url_for("admin.admin_oauth_callback", _external=True)

    # Exchange code
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    token_obj = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": list(creds.scopes or scopes),
        "expiry": creds.expiry.isoformat() if getattr(creds, "expiry", None) else None
    }

    # Try to save to disk (token.json path) — fallback is to display JSON for manual copy
    token_path = os.getenv("GOOGLE_SERVICE_TOKEN_JSON", "token.json")
    try:
        with open(token_path, "w", encoding="utf-8") as f:
            json.dump(token_obj, f)
        # Try to read Drive user email to confirm
        try:
            creds_obj = UserCredentials.from_authorized_user_info(token_obj, scopes=scopes)
            svc = build("drive", "v3", credentials=creds_obj, cache_discovery=False)
            about = svc.about().get(fields="user").execute()
            email = about.get("user", {}).get("emailAddress", "unknown")
            return f"Success — token saved to <code>{token_path}</code>. Authorized as: {email}"
        except Exception:
            return f"Success — token saved to <code>{token_path}</code>. Authorization complete."
    except Exception as e:
        # If cannot write, return token JSON so user can copy-paste into Render env
        pretty = json.dumps(token_obj, indent=2)
        return (
            "Could not write token.json on server. Copy the JSON below and set it as the value of the "
            "<code>GOOGLE_SERVICE_TOKEN_JSON</code> environment variable in Render (paste full JSON):"
            + "<pre>" + pretty + "</pre>"
        )

# --- END: Web OAuth routes for admin ---

@admin_bp.route("/attempts")
@admin_required
def attempts():
    sa = create_drive_service()
    users_df = load_csv_from_drive(sa, USERS_FILE_ID)
    exams_df = load_csv_from_drive(sa, EXAMS_FILE_ID)
    attempts_df = load_csv_from_drive(sa, EXAM_ATTEMPTS_FILE_ID)

    if users_df is None: users_df = pd.DataFrame()
    if exams_df is None: exams_df = pd.DataFrame()
    if attempts_df is None: attempts_df = pd.DataFrame()

    rows = []
    for _, u in users_df.iterrows():
        for _, e in exams_df.iterrows():
            student_id, exam_id = str(u["id"]), str(e["id"])
            user_attempts = attempts_df[(attempts_df["student_id"].astype(str)==student_id) &
                                        (attempts_df["exam_id"].astype(str)==exam_id)]
            used = len(user_attempts)
            
            # More robust max_attempts handling
            max_att_raw = e.get("max_attempts", "")
            
            # Convert to string and strip
            if pd.isna(max_att_raw):
                max_att = ""
            else:
                max_att = str(max_att_raw).strip()
            
            # Calculate remaining
            if max_att == "" or max_att == "0" or max_att.lower() == "nan":
                remaining = "∞"
                display_max = "∞"
            else:
                try:
                    max_attempts_int = int(float(max_att))  # Handle case where it's stored as float string
                    remaining = max(max_attempts_int - used, 0)
                    display_max = str(max_attempts_int)
                except (ValueError, TypeError):
                    remaining = "?"
                    display_max = max_att
            
            rows.append({
                "student_id": student_id,
                "username": u.get("username"),
                "exam_id": exam_id,
                "exam_name": e.get("name"),
                "max_attempts": display_max,
                "attempts_used": used,
                "remaining": remaining
            })
    
    return render_template("admin/attempts.html", rows=rows)


@admin_bp.route("/attempts/modify", methods=["POST"])
@admin_required
def attempts_modify():
    sa = create_drive_service()
    payload = request.get_json(force=True)
    student_id = str(payload.get("student_id"))
    exam_id = str(payload.get("exam_id"))
    action = payload.get("action")
    amount = int(payload.get("amount") or 0)

    attempts_df = load_csv_from_drive(sa, EXAM_ATTEMPTS_FILE_ID)
    if attempts_df is None: 
        attempts_df = pd.DataFrame(columns=["id","student_id","exam_id","attempt_number","status","start_time","end_time"])

    mask = (attempts_df["student_id"].astype(str)==student_id) & (attempts_df["exam_id"].astype(str)==exam_id)
    current = attempts_df[mask]
    used = len(current)

    if action == "reset":
        attempts_df = attempts_df[~mask]
    elif action == "decrease":
        drop_ids = current.tail(amount)["id"].tolist()
        attempts_df = attempts_df[~attempts_df["id"].isin(drop_ids)]
    elif action == "increase":
        start_id = (attempts_df["id"].astype(int).max() + 1) if not attempts_df.empty else 1
        for i in range(amount):
            attempts_df = pd.concat([attempts_df, pd.DataFrame([{
                "id": start_id+i,
                "student_id": student_id,
                "exam_id": exam_id,
                "attempt_number": used+i+1,
                "status": "manual_add",
                "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": ""
            }])], ignore_index=True)

    # Use save_csv_to_drive directly instead of safe_csv_save_with_retry
    ok = save_csv_to_drive(sa, attempts_df, EXAM_ATTEMPTS_FILE_ID)
    if ok:
        clear_cache()
        return jsonify({"success": True})
    return jsonify({"success": False}), 500




@admin_bp.route("/requests")
@admin_required
def requests_dashboard():
    """Requests dashboard with new and history tabs"""
    return render_template("admin/requests.html")

@admin_bp.route("/requests/new")
@admin_required
def new_requests():
    """View new (pending) access requests"""
    try:
        service = create_drive_service()
        
        # Load requests data
        requests_df = load_csv_from_drive(service, REQUESTS_RAISED_FILE_ID)
        if requests_df is None:
            requests_df = pd.DataFrame(columns=[
                'request_id', 'username', 'email', 'current_access',
                'requested_access', 'request_date', 'request_status', 'reason'
            ])
        
        # Filter pending requests
        if not requests_df.empty:
            pending_requests = requests_df[
                requests_df['request_status'].astype(str).str.lower() == 'pending'
            ].sort_values('request_date', ascending=False)
        else:
            pending_requests = pd.DataFrame()
        
        # Convert to list of dictionaries for template
        requests_list = []
        for _, row in pending_requests.iterrows():
            requests_list.append({
                'request_id': int(row['request_id']),
                'username': row['username'],
                'email': row['email'],
                'current_access': row['current_access'],
                'requested_access': row['requested_access'],
                'request_date': row['request_date'],
                'status': row['request_status']
            })
        
        return render_template("admin/new_requests.html", requests=requests_list)
        
    except Exception as e:
        print(f"Error loading new requests: {e}")
        flash("Error loading requests data.", "error")
        return render_template("admin/new_requests.html", requests=[])

@admin_bp.route("/requests/history")
@admin_required
def requests_history():
    """View completed/denied requests history"""
    try:
        service = create_drive_service()
        
        # Load requests data
        requests_df = load_csv_from_drive(service, REQUESTS_RAISED_FILE_ID)
        if requests_df is None:
            requests_df = pd.DataFrame()
        
        # Filter completed/denied requests
        history_requests = []
        if not requests_df.empty:
            history_df = requests_df[
                requests_df['request_status'].astype(str).str.lower().isin(['completed', 'denied'])
            ].sort_values('request_date', ascending=False)
            
            for _, row in history_df.iterrows():
                history_requests.append({
                    'request_id': int(row['request_id']),
                    'username': row['username'],
                    'email': row['email'],
                    'current_access': row['current_access'],
                    'requested_access': row['requested_access'],
                    'request_date': row['request_date'],
                    'status': row['request_status'],
                    'reason': row.get('reason', ''),
                    'processed_by': row.get('processed_by', 'Admin'),
                    'processed_date': row.get('processed_date', '')
                })
        
        return render_template("admin/requests_history.html", requests=history_requests)
        
    except Exception as e:
        print(f"Error loading requests history: {e}")
        flash("Error loading requests history.", "error")
        return render_template("admin/requests_history.html", requests=[])

@admin_bp.route("/requests/approve/<int:request_id>", methods=["POST"])
@admin_required
def approve_request(request_id):
    """Approve an access request"""
    try:
        data = request.get_json()
        approved_access = data.get('approved_access')
        
        if not approved_access:
            return jsonify({
                'success': False,
                'message': 'Please select an access level to approve'
            }), 400
        
        service = create_drive_service()
        
        # Load requests data
        requests_df = load_csv_from_drive(service, REQUESTS_RAISED_FILE_ID)
        if requests_df is None or requests_df.empty:
            return jsonify({
                'success': False,
                'message': 'No requests found'
            }), 404
        
        # Find the specific request
        request_row = requests_df[
            (requests_df['request_id'].astype(int) == request_id) &
            (requests_df['request_status'].astype(str).str.lower() == 'pending')
        ]
        
        if request_row.empty:
            return jsonify({
                'success': False,
                'message': 'Request not found or already processed'
            }), 404
        
        request_data = request_row.iloc[0]
        username = request_data['username']
        email = request_data['email']
        
        # Load users data and update access
        users_df = load_csv_from_drive(service, USERS_FILE_ID)
        if users_df is None or users_df.empty:
            return jsonify({
                'success': False,
                'message': 'Users database unavailable'
            }), 500
        
        # Find and update user
        users_df['username_lower'] = users_df['username'].astype(str).str.strip().str.lower()
        users_df['email_lower'] = users_df['email'].astype(str).str.strip().str.lower()
        
        user_mask = (
            (users_df['username_lower'] == username.lower()) &
            (users_df['email_lower'] == email.lower())
        )
        
        if not user_mask.any():
            return jsonify({
                'success': False,
                'message': 'User not found in database'
            }), 404
        
        # Update user access
        users_df.loc[user_mask, 'role'] = approved_access
        users_df.loc[user_mask, 'updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Update request status
        request_mask = requests_df['request_id'].astype(int) == request_id
        requests_df.loc[request_mask, 'request_status'] = 'completed'
        requests_df.loc[request_mask, 'reason'] = f'Approved: {approved_access}'
        requests_df.loc[request_mask, 'processed_by'] = session.get('admin_name', 'Admin')
        requests_df.loc[request_mask, 'processed_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Save both files
        users_success = safe_csv_save_with_retry(users_df, 'users')
        requests_success = safe_csv_save_with_retry(requests_df, 'requests_raised')
        
        if users_success and requests_success:
            clear_cache()
            return jsonify({
                'success': True,
                'message': f'Request approved successfully. User {username} now has {approved_access} access.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Error saving approval. Please try again.'
            }), 500
        
    except Exception as e:
        print(f"Error approving request: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': 'System error occurred'
        }), 500

@admin_bp.route("/requests/deny/<int:request_id>", methods=["POST"])
@admin_required
def deny_request(request_id):
    """Deny an access request with reason"""
    try:
        data = request.get_json()
        denial_reason = data.get('reason', '').strip()
        
        if not denial_reason:
            return jsonify({
                'success': False,
                'message': 'Please provide a reason for denial'
            }), 400
        
        service = create_drive_service()
        
        # Load requests data
        requests_df = load_csv_from_drive(service, REQUESTS_RAISED_FILE_ID)
        if requests_df is None or requests_df.empty:
            return jsonify({
                'success': False,
                'message': 'No requests found'
            }), 404
        
        # Find the specific request
        request_row = requests_df[
            (requests_df['request_id'].astype(int) == request_id) &
            (requests_df['request_status'].astype(str).str.lower() == 'pending')
        ]
        
        if request_row.empty:
            return jsonify({
                'success': False,
                'message': 'Request not found or already processed'
            }), 404
        
        # Update request status
        request_mask = requests_df['request_id'].astype(int) == request_id
        requests_df.loc[request_mask, 'request_status'] = 'denied'
        requests_df.loc[request_mask, 'reason'] = denial_reason
        requests_df.loc[request_mask, 'processed_by'] = session.get('admin_name', 'Admin')
        requests_df.loc[request_mask, 'processed_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Save requests file
        success = safe_csv_save_with_retry(requests_df, 'requests_raised')
        
        if success:
            clear_cache()
            return jsonify({
                'success': True,
                'message': f'Request denied successfully.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Error saving denial. Please try again.'
            }), 500
        
    except Exception as e:
        print(f"Error denying request: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': 'System error occurred'
        }), 500

@admin_bp.route("/api/requests/stats")
@admin_required
def api_requests_stats():
    """API endpoint for request statistics"""
    try:
        service = create_drive_service()
        
        # Load requests data
        requests_df = load_csv_from_drive(service, REQUESTS_RAISED_FILE_ID)
        if requests_df is None or requests_df.empty:
            return jsonify({
                'pending': 0,
                'completed': 0,
                'denied': 0,
                'total': 0
            })
        
        # Count by status
        status_counts = requests_df['request_status'].astype(str).str.lower().value_counts()
        
        return jsonify({
            'pending': int(status_counts.get('pending', 0)),
            'completed': int(status_counts.get('completed', 0)),
            'denied': int(status_counts.get('denied', 0)),
            'total': len(requests_df)
        })
        
    except Exception as e:
        print(f"Error getting request stats: {e}")
        return jsonify({
            'pending': 0,
            'completed': 0,
            'denied': 0,
            'total': 0
        })




# Add these routes to your admin.py file

@admin_bp.route("/users/manage")
@admin_required
def users_manage():
    """View users management page"""
    try:
        service = create_drive_service()
        
        # Load users data
        users_df = load_csv_from_drive(service, USERS_FILE_ID)
        if users_df is None:
            users_df = pd.DataFrame(columns=[
                'id', 'username', 'email', 'full_name', 'role', 'created_at', 'updated_at'
            ])
        
        # Prepare users data (exclude sensitive information)
        users_list = []
        if not users_df.empty:
            for _, row in users_df.iterrows():
                users_list.append({
                    'id': int(row['id']),
                    'username': row.get('username', ''),
                    'email': row.get('email', ''),
                    'full_name': row.get('full_name', ''),
                    'role': row.get('role', 'user'),
                    'created_at': row.get('created_at', ''),
                    'updated_at': row.get('updated_at', '')
                })
        
        # Sort by username
        users_list.sort(key=lambda x: x['username'].lower())
        
        return render_template("admin/users_manage.html", users=users_list)
        
    except Exception as e:
        print(f"Error loading users management: {e}")
        flash("Error loading users data.", "error")
        return render_template("admin/users_manage.html", users=[])

@admin_bp.route("/users/update-role", methods=["POST"])
@admin_required
def update_user_role():
    """Update user role"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        new_role = data.get('new_role', '').strip()
        
        if not user_id or not new_role:
            return jsonify({
                'success': False,
                'message': 'User ID and role are required'
            }), 400
        
        # Validate role
        valid_roles = ['user', 'admin', 'user,admin']
        if new_role not in valid_roles:
            return jsonify({
                'success': False,
                'message': 'Invalid role selected'
            }), 400
        
        service = create_drive_service()
        
        # Load users data
        users_df = load_csv_from_drive(service, USERS_FILE_ID)
        if users_df is None or users_df.empty:
            return jsonify({
                'success': False,
                'message': 'Users database unavailable'
            }), 500
        
        # Find user
        user_mask = users_df['id'].astype(str) == str(user_id)
        if not user_mask.any():
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 404
        
        # Get current user info
        user_row = users_df[user_mask].iloc[0]
        username = user_row['username']
        current_role = user_row.get('role', 'user')
        
        # Check if role actually changed
        if current_role == new_role:
            return jsonify({
                'success': True,
                'message': f'User {username} already has {new_role} role',
                'no_change': True
            })
        
        # Update user role
        users_df.loc[user_mask, 'role'] = new_role
        users_df.loc[user_mask, 'updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Save to CSV
        success = safe_csv_save_with_retry(users_df, 'users')
        
        if success:
            clear_cache()
            return jsonify({
                'success': True,
                'message': f'Successfully updated {username} role from {current_role} to {new_role}',
                'user_id': user_id,
                'new_role': new_role,
                'username': username
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Error saving role update. Please try again.'
            }), 500
        
    except Exception as e:
        print(f"Error updating user role: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': 'System error occurred'
        }), 500

@admin_bp.route("/users/bulk-update-roles", methods=["POST"])
@admin_required
def bulk_update_user_roles():
    """Bulk update multiple user roles"""
    try:
        data = request.get_json()
        updates = data.get('updates', [])
        
        if not updates:
            return jsonify({
                'success': False,
                'message': 'No updates provided'
            }), 400
        
        service = create_drive_service()
        users_df = load_csv_from_drive(service, USERS_FILE_ID)
        
        if users_df is None or users_df.empty:
            return jsonify({
                'success': False,
                'message': 'Users database unavailable'
            }), 500
        
        valid_roles = ['user', 'admin', 'user,admin']
        updated_count = 0
        errors = []
        
        for update in updates:
            user_id = update.get('user_id')
            new_role = update.get('new_role', '').strip()
            
            if not user_id or not new_role:
                errors.append(f'Invalid update data for user {user_id}')
                continue
                
            if new_role not in valid_roles:
                errors.append(f'Invalid role {new_role} for user {user_id}')
                continue
            
            user_mask = users_df['id'].astype(str) == str(user_id)
            if not user_mask.any():
                errors.append(f'User {user_id} not found')
                continue
            
            # Update role
            users_df.loc[user_mask, 'role'] = new_role
            users_df.loc[user_mask, 'updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            updated_count += 1
        
        if updated_count > 0:
            success = safe_csv_save_with_retry(users_df, 'users')
            if success:
                clear_cache()
                message = f'Successfully updated {updated_count} user roles'
                if errors:
                    message += f' ({len(errors)} errors occurred)'
                
                return jsonify({
                    'success': True,
                    'message': message,
                    'updated_count': updated_count,
                    'errors': errors
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Error saving bulk updates'
                }), 500
        else:
            return jsonify({
                'success': False,
                'message': 'No valid updates to apply',
                'errors': errors
            }), 400
        
    except Exception as e:
        print(f"Error in bulk update: {e}")
        return jsonify({
            'success': False,
            'message': 'System error occurred'
        }), 500

@admin_bp.route("/api/users/stats")
@admin_required
def api_users_stats():
    """API endpoint for user statistics"""
    try:
        service = create_drive_service()
        users_df = load_csv_from_drive(service, USERS_FILE_ID)
        
        if users_df is None or users_df.empty:
            return jsonify({
                'total_users': 0,
                'user_role': 0,
                'admin_role': 0,
                'both_roles': 0
            })
        
        # Count by role
        role_counts = {'user': 0, 'admin': 0, 'both': 0}
        
        for _, row in users_df.iterrows():
            role = str(row.get('role', 'user')).lower().strip()
            if ',' in role or 'user' in role and 'admin' in role:
                role_counts['both'] += 1
            elif 'admin' in role:
                role_counts['admin'] += 1
            else:
                role_counts['user'] += 1
        
        return jsonify({
            'total_users': len(users_df),
            'user_role': role_counts['user'],
            'admin_role': role_counts['admin'],
            'both_roles': role_counts['both']
        })
        
    except Exception as e:
        print(f"Error getting user stats: {e}")
        return jsonify({
            'total_users': 0,
            'user_role': 0,
            'admin_role': 0,
            'both_roles': 0
        })        