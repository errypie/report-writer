"""Pentest Report Writer — Flask app for writing uniform penetration-test reports."""
import base64
import io
import json
import os
import re
import sqlite3
import uuid
from datetime import date, datetime

import nh3
from flask import (Flask, Response, abort, g, jsonify, redirect, render_template,
                   request, send_file, send_from_directory, url_for)

from cvss import cvss31
from library_seed import seed_templates
from report_texts import (CALLOUTS, CLASS_COLORS, CLASSIFICATIONS, DEFAULT_TEXTS, LABELS, SEVERITIES,
                          SEVERITY_ORDER, normalize_classification)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("REPORTS_DB", os.path.join(BASE_DIR, "reports.db"))
UPLOAD_DIR = os.environ.get("REPORTS_UPLOADS", os.path.join(BASE_DIR, "uploads"))
BACKUP_DIR = os.environ.get("REPORTS_BACKUPS", os.path.join(BASE_DIR, "backups"))
BACKUPS_KEPT = 30
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # JSON imports may carry inlined screenshots
MAX_IMAGE_BYTES = 15 * 1024 * 1024
IMAGE_TYPES = {  # magic bytes -> extension
    b"\x89PNG\r\n\x1a\n": "png", b"\xff\xd8\xff": "jpg", b"GIF87a": "gif", b"GIF89a": "gif",
}
UPLOAD_NAME_RE = re.compile(r"^[0-9a-f]{32}\.(png|jpg|gif|webp)$")

REPORT_TEXT_FIELDS = {
    "title", "client", "system_name", "test_type", "start_date", "end_date",
    "version", "classification", "authors", "lang",
}
REPORT_RICH_FIELDS = {"executive_summary", "scope", "methodology", "conclusion"}
FINDING_TEXT_FIELDS = {"title", "severity", "cvss_score", "cvss_vector", "cwe", "assets", "status"}
FINDING_RICH_FIELDS = {"description", "impact", "reproduction", "recommendation", "refs"}

ALLOWED_TAGS = {
    "p", "br", "b", "strong", "i", "em", "u", "s", "strike", "sub", "sup", "h3", "h4",
    "ul", "ol", "li", "pre", "code", "blockquote", "a", "img", "hr", "span", "div",
    "table", "thead", "tbody", "tr", "th", "td", "figure", "figcaption",
}
ALLOWED_ATTRS = {
    "a": {"href", "title"},
    "img": {"src", "alt", "width"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan"},
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL DEFAULT '',
    client TEXT NOT NULL DEFAULT '',
    system_name TEXT NOT NULL DEFAULT '',
    test_type TEXT NOT NULL DEFAULT '',
    start_date TEXT NOT NULL DEFAULT '',
    end_date TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '1.0',
    classification TEXT NOT NULL DEFAULT '',
    authors TEXT NOT NULL DEFAULT '',
    lang TEXT NOT NULL DEFAULT 'ru',
    executive_summary TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT '',
    methodology TEXT NOT NULL DEFAULT '',
    conclusion TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    cvss_score TEXT NOT NULL DEFAULT '',
    cvss_vector TEXT NOT NULL DEFAULT '',
    cwe TEXT NOT NULL DEFAULT '',
    assets TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    description TEXT NOT NULL DEFAULT '',
    impact TEXT NOT NULL DEFAULT '',
    reproduction TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    refs TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS library (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lang TEXT NOT NULL DEFAULT 'ru',
    title TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    cvss_score TEXT NOT NULL DEFAULT '',
    cvss_vector TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    impact TEXT NOT NULL DEFAULT '',
    reproduction TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    refs TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
"""
LIBRARY_FIELDS = ["title", "severity", "cvss_score", "cvss_vector", "description", "impact",
                  "reproduction", "recommendation", "refs"]


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript(SCHEMA)
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version < 1:  # first run with the library: add the built-in templates once
            ts = datetime.now().isoformat(timespec="seconds")
            for t in seed_templates():
                score = cvss31(t["cvss_vector"])
                db.execute(
                    "INSERT INTO library (lang, title, severity, cvss_score, cvss_vector, description,"
                    " impact, reproduction, recommendation, refs, updated_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (t["lang"], t["title"], score[1], "%.1f" % score[0], t["cvss_vector"],
                     t["description"], t["impact"], t.get("reproduction", ""),
                     t["recommendation"], t.get("refs", ""), ts),
                )
            db.execute("PRAGMA user_version = 1")
            version = 1
        if version < 2:  # classification became a fixed list of categories
            for rid, value in db.execute("SELECT id, classification FROM reports").fetchall():
                db.execute("UPDATE reports SET classification = ? WHERE id = ?",
                           (normalize_classification(value), rid))
            db.execute("PRAGMA user_version = 2")


# ---------------------------------------------------------------- backups
def backup_db(min_age_hours=0.2):
    """Copy the database into BACKUP_DIR (safe while the app is running) and keep the newest copies.
    Skipped if the newest backup is younger than `min_age_hours`."""
    if not os.path.exists(DB_PATH):
        return None
    existing = sorted(f for f in os.listdir(BACKUP_DIR) if f.startswith("reports-") and f.endswith(".db"))
    if existing:
        age = datetime.now().timestamp() - os.path.getmtime(os.path.join(BACKUP_DIR, existing[-1]))
        if age < min_age_hours * 3600:
            return None
    target = os.path.join(BACKUP_DIR, "reports-%s.db" % datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
    with sqlite3.connect(DB_PATH) as src, sqlite3.connect(target) as dst:
        src.backup(dst)
    existing.append(os.path.basename(target))
    for old in existing[:-BACKUPS_KEPT]:
        os.remove(os.path.join(BACKUP_DIR, old))
    return target


def cleanup_uploads(min_age_hours=24):
    """Delete screenshot files no report, finding or template refers to any more — e.g. the
    unredacted original after an image was edited. Files younger than a day are kept so undo works."""
    with sqlite3.connect(DB_PATH) as db:
        texts = [r[0] for r in db.execute(
            "SELECT executive_summary || scope || methodology || conclusion FROM reports "
            "UNION ALL SELECT description || impact || reproduction || recommendation || refs FROM findings "
            "UNION ALL SELECT description || impact || reproduction || recommendation || refs FROM library")]
    used = set(UPLOAD_SRC_RE.findall(" ".join(t or "" for t in texts)))
    cutoff = datetime.now().timestamp() - min_age_hours * 3600
    removed = 0
    for name in os.listdir(UPLOAD_DIR):
        path = os.path.join(UPLOAD_DIR, name)
        if UPLOAD_NAME_RE.match(name) and name not in used and os.path.getmtime(path) < cutoff:
            os.remove(path)
            removed += 1
    return removed


@app.before_request
def daily_backup():
    # Cheap check: at most one file-system look per hour, a new copy once a day while the app runs.
    last = getattr(app, "_backup_checked", 0)
    if datetime.now().timestamp() - last > 3600:
        app._backup_checked = datetime.now().timestamp()
        backup_db(min_age_hours=24)
        cleanup_uploads()


def now():
    return datetime.now().isoformat(timespec="seconds")


# ---------------------------------------------------------------- images
def save_image(data):
    """Store image bytes in UPLOAD_DIR and return its public URL, or None if not an image."""
    if not data or len(data) > MAX_IMAGE_BYTES:
        return None
    ext = next((e for magic, e in IMAGE_TYPES.items() if data.startswith(magic)), None)
    if ext is None and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        ext = "webp"
    if ext is None:
        return None
    name = "%s.%s" % (uuid.uuid4().hex, ext)
    with open(os.path.join(UPLOAD_DIR, name), "wb") as fh:
        fh.write(data)
    return "/uploads/" + name


DATA_URI_RE = re.compile(r'src="data:image/[a-z+.-]+;base64,([A-Za-z0-9+/=\s]+)"')
UPLOAD_SRC_RE = re.compile(r'src="/uploads/([0-9a-f]{32}\.(?:png|jpg|gif|webp))"')


def extract_inline_images(html):
    """Move base64 images (pasted or imported) out of the HTML into uploaded files."""
    def repl(m):
        try:
            url = save_image(base64.b64decode(m.group(1)))
        except ValueError:
            url = None
        return 'src="%s"' % url if url else 'src=""'
    return DATA_URI_RE.sub(repl, html)


def inline_uploaded_images(html):
    """Reverse of extract_inline_images, used for the portable JSON export."""
    def repl(m):
        path = os.path.join(UPLOAD_DIR, m.group(1))
        if not os.path.exists(path):
            return m.group(0)
        mime = {"jpg": "jpeg"}.get(m.group(1).rsplit(".", 1)[1], m.group(1).rsplit(".", 1)[1])
        with open(path, "rb") as fh:
            return 'src="data:image/%s;base64,%s"' % (mime, base64.b64encode(fh.read()).decode())
    return UPLOAD_SRC_RE.sub(repl, html or "")


def sanitize(html):
    html = extract_inline_images(html or "")
    return nh3.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        url_schemes={"http", "https", "mailto"},
        allowed_classes={"div": {"callout"} | {"callout-" + c for c in CALLOUTS}},
        link_rel="noopener noreferrer",
    )


def decorate(report):
    """Add display-only fields derived from the stored classification key."""
    key = normalize_classification(report["classification"])
    report["class_key"] = key
    report["class_label"] = LABELS[report["lang"]]["classes"][key]
    report["class_color"] = CLASS_COLORS[key]
    return report


def load_report(report_id):
    row = get_db().execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if row is None:
        abort(404)
    return decorate(dict(row))


def load_findings(report_id):
    rows = get_db().execute(
        "SELECT * FROM findings WHERE report_id = ? ORDER BY position, id", (report_id,)
    ).fetchall()
    findings = [dict(r) for r in rows]
    # Every report uses the same ordering: by severity, then by creation order.
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["position"], f["id"]))
    for i, f in enumerate(findings, 1):
        f["code"] = "F-%02d" % i
    return findings


def severity_counts(findings):
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1
    return counts


def touch(report_id):
    get_db().execute("UPDATE reports SET updated_at = ? WHERE id = ?", (now(), report_id))


def create_report(lang="ru", data=None):
    data = data or {}
    texts = DEFAULT_TEXTS[lang]
    ts = now()
    cur = get_db().execute(
        """INSERT INTO reports (title, client, system_name, test_type, start_date, end_date,
           version, classification, authors, lang, executive_summary, scope, methodology,
           conclusion, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            data.get("title", texts["title"]),
            data.get("client", ""),
            data.get("system_name", ""),
            data.get("test_type", texts["test_type"]),
            data.get("start_date", date.today().isoformat()),
            data.get("end_date", date.today().isoformat()),
            data.get("version", "1.0"),
            normalize_classification(data.get("classification", texts["classification"])),
            data.get("authors", ""),
            lang,
            sanitize(data.get("executive_summary", texts["executive_summary"])),
            sanitize(data.get("scope", texts["scope"])),
            sanitize(data.get("methodology", texts["methodology"])),
            sanitize(data.get("conclusion", texts["conclusion"])),
            ts,
            ts,
        ),
    )
    return cur.lastrowid


def insert_finding(report_id, data=None):
    data = data or {}
    db = get_db()
    pos = db.execute(
        "SELECT COALESCE(MAX(position), 0) + 1 FROM findings WHERE report_id = ?", (report_id,)
    ).fetchone()[0]
    severity = data.get("severity", "medium")
    if severity not in SEVERITIES:
        severity = "medium"
    cur = db.execute(
        """INSERT INTO findings (report_id, position, title, severity, cvss_score, cvss_vector,
           cwe, assets, status, description, impact, reproduction, recommendation, refs)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            report_id, pos,
            data.get("title", ""), severity,
            data.get("cvss_score", ""), data.get("cvss_vector", ""),
            data.get("cwe", ""), data.get("assets", ""), data.get("status", "open"),
            sanitize(data.get("description", "")), sanitize(data.get("impact", "")),
            sanitize(data.get("reproduction", "")), sanitize(data.get("recommendation", "")),
            sanitize(data.get("refs", "")),
        ),
    )
    return cur.lastrowid


# ---------------------------------------------------------------- pages
@app.template_filter("css_string")
def css_string(value):
    """Quote a value for use in a CSS `content:` declaration."""
    value = str(value or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    return '"%s"' % value.replace("<", "\\3c ")


def fmt_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").strftime("%d.%m.%Y")
    except (TypeError, ValueError):
        return value or ""


app.add_template_filter(fmt_date, "date")


@app.context_processor
def inject_globals():
    return {"SEVERITIES": SEVERITIES, "CLASSIFICATIONS": CLASSIFICATIONS, "CALLOUTS": CALLOUTS,
            "CLASS_COLORS": CLASS_COLORS,
            "BRAND": "СберБанк"}


@app.route("/")
def dashboard():
    db = get_db()
    reports = [decorate(dict(r)) for r in db.execute("SELECT * FROM reports ORDER BY updated_at DESC")]
    for r in reports:
        r["counts"] = severity_counts(load_findings(r["id"]))
        r["total"] = sum(r["counts"].values())
    return render_template("dashboard.html", reports=reports)


@app.route("/reports", methods=["POST"])
def new_report():
    lang = request.form.get("lang", "ru")
    if lang not in DEFAULT_TEXTS:
        lang = "ru"
    report_id = create_report(lang)
    get_db().commit()
    return redirect(url_for("editor", report_id=report_id))


@app.route("/reports/<int:report_id>")
def editor(report_id):
    report = load_report(report_id)
    findings = load_findings(report_id)
    return render_template(
        "editor.html", report=report, findings=findings,
        counts=severity_counts(findings), L=LABELS[report["lang"]],
    )


@app.route("/reports/<int:report_id>/preview")
def preview(report_id):
    report = load_report(report_id)
    findings = load_findings(report_id)
    return render_template(
        "report.html", report=report, findings=findings,
        counts=severity_counts(findings), L=LABELS[report["lang"]],
        generated=date.today().isoformat(),
    )


@app.route("/reports/<int:report_id>/duplicate", methods=["POST"])
def duplicate(report_id):
    report = load_report(report_id)
    report["title"] = report["title"] + (" (копия)" if report["lang"] == "ru" else " (copy)")
    new_id = create_report(report["lang"], report)
    for f in load_findings(report_id):
        insert_finding(new_id, f)
    get_db().commit()
    return redirect(url_for("editor", report_id=new_id))


@app.route("/reports/<int:report_id>/delete", methods=["POST"])
def delete(report_id):
    load_report(report_id)
    db = get_db()
    db.execute("DELETE FROM findings WHERE report_id = ?", (report_id,))
    db.execute("DELETE FROM reports WHERE id = ?", (report_id,))
    db.commit()
    return redirect(url_for("dashboard"))


@app.route("/reports/<int:report_id>/export.json")
def export_json(report_id):
    report = load_report(report_id)
    findings = load_findings(report_id)
    for f in findings:
        for k in ("id", "report_id", "code"):
            f.pop(k, None)
        for k in FINDING_RICH_FIELDS:
            f[k] = inline_uploaded_images(f[k])
    for k in ("id", "class_key", "class_label", "class_color"):
        report.pop(k, None)
    for k in REPORT_RICH_FIELDS:  # screenshots travel inside the JSON file
        report[k] = inline_uploaded_images(report[k])
    payload = {"format": "pentest-report/1", "report": report, "findings": findings}
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": 'attachment; filename="report-%d.json"' % report_id},
    )


@app.route("/import", methods=["POST"])
def import_json():
    file = request.files.get("file")
    if not file:
        abort(400)
    try:
        payload = json.load(file)
        report = payload["report"]
        findings = payload.get("findings", [])
    except (ValueError, KeyError, TypeError):
        abort(400)
    lang = report.get("lang", "ru")
    if lang not in DEFAULT_TEXTS:
        lang = "ru"
    new_id = create_report(lang, report)
    for f in findings:
        insert_finding(new_id, f)
    get_db().commit()
    return redirect(url_for("editor", report_id=new_id))


# ---------------------------------------------------------------- JSON API (autosave)
@app.route("/api/reports/<int:report_id>", methods=["PATCH"])
def api_update_report(report_id):
    load_report(report_id)
    data = request.get_json(force=True) or {}
    db = get_db()
    for key, value in data.items():
        if key in REPORT_TEXT_FIELDS:
            if key == "lang" and value not in DEFAULT_TEXTS:
                continue
            if key == "classification" and value not in CLASSIFICATIONS:
                continue
            db.execute("UPDATE reports SET %s = ? WHERE id = ?" % key, (str(value), report_id))
        elif key in REPORT_RICH_FIELDS:
            db.execute("UPDATE reports SET %s = ? WHERE id = ?" % key, (sanitize(value), report_id))
    touch(report_id)
    db.commit()
    return jsonify(ok=True, updated_at=now())


@app.route("/api/reports/<int:report_id>/findings", methods=["POST"])
def api_add_finding(report_id):
    report = load_report(report_id)
    tpl = dict(DEFAULT_TEXTS[report["lang"]]["finding"])
    template_id = (request.get_json(silent=True) or {}).get("template_id")
    if template_id:
        row = get_db().execute("SELECT * FROM library WHERE id = ?", (template_id,)).fetchone()
        if row is None:
            abort(404)
        tpl = {k: row[k] for k in LIBRARY_FIELDS}
        if not tpl["reproduction"]:
            tpl["reproduction"] = DEFAULT_TEXTS[report["lang"]]["finding"]["reproduction"]
    fid = insert_finding(report_id, tpl)
    touch(report_id)
    get_db().commit()
    finding = next(f for f in load_findings(report_id) if f["id"] == fid)
    html = render_template("_finding.html", f=finding, L=LABELS[report["lang"]])
    return jsonify(ok=True, id=fid, html=html)


def load_finding(fid):
    row = get_db().execute("SELECT * FROM findings WHERE id = ?", (fid,)).fetchone()
    if row is None:
        abort(404)
    return dict(row)


@app.route("/api/findings/<int:fid>", methods=["PATCH"])
def api_update_finding(fid):
    finding = load_finding(fid)
    data = request.get_json(force=True) or {}
    db = get_db()
    for key, value in data.items():
        if key in FINDING_TEXT_FIELDS:
            if key == "severity" and value not in SEVERITIES:
                continue
            db.execute("UPDATE findings SET %s = ? WHERE id = ?" % key, (str(value), fid))
        elif key in FINDING_RICH_FIELDS:
            db.execute("UPDATE findings SET %s = ? WHERE id = ?" % key, (sanitize(value), fid))
    touch(finding["report_id"])
    db.commit()
    return jsonify(ok=True, updated_at=now())


@app.route("/api/findings/<int:fid>", methods=["DELETE"])
def api_delete_finding(fid):
    finding = load_finding(fid)
    db = get_db()
    db.execute("DELETE FROM findings WHERE id = ?", (fid,))
    touch(finding["report_id"])
    db.commit()
    return jsonify(ok=True)


@app.route("/api/reports/<int:report_id>/summary")
def api_summary(report_id):
    load_report(report_id)
    findings = load_findings(report_id)
    return jsonify(
        counts=severity_counts(findings),
        findings=[{"id": f["id"], "code": f["code"], "title": f["title"],
                   "severity": f["severity"]} for f in findings],
    )


# ---------------------------------------------------------------- uploads
@app.route("/api/uploads", methods=["POST"])
def api_upload():
    file = request.files.get("file")
    url = save_image(file.read()) if file else None
    if not url:
        return jsonify(ok=False, error="Поддерживаются PNG, JPEG, GIF и WebP до 15 МБ"), 400
    return jsonify(ok=True, url=url)


@app.route("/uploads/<name>")
def uploaded(name):
    if not UPLOAD_NAME_RE.match(name):
        abort(404)
    return send_from_directory(UPLOAD_DIR, name, max_age=86400)


# ---------------------------------------------------------------- vulnerability library
def library_rows(lang=None):
    sql, args = "SELECT * FROM library", ()
    if lang:
        sql, args = sql + " WHERE lang = ?", (lang,)
    rows = [dict(r) for r in get_db().execute(sql, args)]
    rows.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity"], 99), r["title"].lower()))
    return rows


@app.route("/library")
def library_page():
    lang = request.args.get("lang", "ru")
    if lang not in LABELS:
        lang = "ru"
    return render_template("library.html", templates=library_rows(lang), lang=lang, L=LABELS[lang])


@app.route("/api/library")
def api_library():
    lang = request.args.get("lang", "ru")
    return jsonify([{k: r[k] for k in ("id", "title", "severity", "cvss_score", "cvss_vector")}
                    for r in library_rows(lang)])


@app.route("/api/library/<int:tid>", methods=["DELETE"])
def api_library_delete(tid):
    get_db().execute("DELETE FROM library WHERE id = ?", (tid,))
    get_db().commit()
    return jsonify(ok=True)


@app.route("/api/findings/<int:fid>/to-library", methods=["POST"])
def api_finding_to_library(fid):
    f = load_finding(fid)
    lang = load_report(f["report_id"])["lang"]
    db = get_db()
    existing = db.execute("SELECT id FROM library WHERE lang = ? AND lower(title) = lower(?)",
                          (lang, f["title"].strip())).fetchone()
    # Reproduction steps (and their screenshots) belong to one engagement, so they stay out of templates.
    fields = [k for k in LIBRARY_FIELDS if k != "reproduction"]
    values = [f[k].strip() if k == "title" else f[k] for k in fields]
    if existing:
        db.execute("UPDATE library SET %s, updated_at = ? WHERE id = ?"
                   % ", ".join("%s = ?" % k for k in fields), values + [now(), existing["id"]])
        status = "updated"
    else:
        db.execute("INSERT INTO library (lang, %s, updated_at) VALUES (?, %s, ?)"
                   % (", ".join(fields), ", ".join("?" * len(fields))),
                   [lang] + values + [now()])
        status = "created"
    db.commit()
    return jsonify(ok=True, status=status)


# ---------------------------------------------------------------- Word export
@app.route("/reports/<int:report_id>/export.docx")
def export_docx(report_id):
    from docx_export import build_docx  # imported lazily: python-docx is only needed here
    report = load_report(report_id)
    findings = load_findings(report_id)
    buf = io.BytesIO()
    build_docx(report, findings, severity_counts(findings), LABELS[report["lang"]],
               brand=inject_globals()["BRAND"], upload_dir=UPLOAD_DIR,
               logo_path=os.path.join(BASE_DIR, "static", "img", "logo.png"),
               generated=fmt_date(date.today().isoformat())).save(buf)
    buf.seek(0)
    name = re.sub(r'[\\/:*?"<>|]+', " ", "%s v%s" % (report["title"] or "report", report["version"])).strip()
    return send_file(buf, as_attachment=True, download_name=name + ".docx",
                     mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document")


# ---------------------------------------------------------------- pentest request template
def load_request_template():
    from request_template import DEFAULT_HTML
    row = get_db().execute("SELECT value, updated_at FROM settings WHERE key = 'request_template'").fetchone()
    return (row["value"], row["updated_at"]) if row else (DEFAULT_HTML, "")


@app.route("/request-template")
def request_template_page():
    from request_template import TITLE
    html, updated = load_request_template()
    return render_template("request_template.html", html=html, title=TITLE,
                           updated=updated.replace("T", " ")[:16], custom=bool(updated))


@app.route("/api/request-template", methods=["PUT"])
def request_template_save():
    data = request.get_json(silent=True) or {}
    html = sanitize(data.get("html", ""))
    ts = datetime.now().isoformat(timespec="seconds")
    db = get_db()
    db.execute("INSERT INTO settings (key, value, updated_at) VALUES ('request_template', ?, ?)"
               " ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
               (html, ts))
    db.commit()
    return jsonify(ok=True, updated=ts.replace("T", " ")[:16])


@app.route("/request-template/reset", methods=["POST"])
def request_template_reset():
    db = get_db()
    db.execute("DELETE FROM settings WHERE key = 'request_template'")
    db.commit()
    return redirect(url_for("request_template_page"))


@app.route("/request-template.docx")
def request_template_docx():
    from request_template import TITLE, build_request_docx
    html, _ = load_request_template()
    buf = io.BytesIO()
    build_request_docx(html, TITLE, brand=inject_globals()["BRAND"],
                       logo_path=os.path.join(BASE_DIR, "static", "img", "logo.png"),
                       generated=fmt_date(date.today().isoformat()), upload_dir=UPLOAD_DIR).save(buf)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=TITLE + ".docx",
                     mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document")


init_db()
backup_db()  # a fresh copy on every start
cleanup_uploads()

if __name__ == "__main__":
    # Listens on this computer only. REPORTS_DEBUG=1 enables auto-reload for development.
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 8780)),
            debug=os.environ.get("REPORTS_DEBUG") == "1")
