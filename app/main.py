"""A deliberately small notes API used to demonstrate security gates in CI.

The app is the *subject* of the pipeline, not the point of the repo. Each
security control is commented so it can be explained line by line.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

from flask import Flask, Response, g, jsonify, request

MAX_TITLE = 120
MAX_BODY = 2_000

SECURITY_HEADERS = {
    # The API returns JSON only, so the strictest CSP costs nothing.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def create_app(database: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        DATABASE=database or os.environ.get("NOTES_DB", str(Path(app.instance_path) / "notes.db")),
        MAX_CONTENT_LENGTH=16 * 1024,  # reject oversized request bodies before parsing (HTTP 413)
    )
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc: BaseException | None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    with app.app_context():
        get_db().execute(
            "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT NOT NULL)"
        )
        get_db().commit()

    @app.after_request
    def add_security_headers(response: Response) -> Response:
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    def error(message: str, status: int) -> tuple[Response, int]:
        # Generic, consistent errors: no stack traces or SQL details reach the client.
        return jsonify({"error": message}), status

    @app.errorhandler(404)
    def not_found(_exc: Exception) -> tuple[Response, int]:
        return error("not found", 404)

    @app.errorhandler(405)
    def method_not_allowed(_exc: Exception) -> tuple[Response, int]:
        return error("method not allowed", 405)

    @app.errorhandler(413)
    def too_large(_exc: Exception) -> tuple[Response, int]:
        return error("request body too large", 413)

    @app.errorhandler(500)
    def server_error(_exc: Exception) -> tuple[Response, int]:
        return error("internal error", 500)

    @app.get("/health")
    def health() -> Response:
        return jsonify({"status": "ok"})

    @app.get("/notes")
    def list_notes() -> Response:
        rows = get_db().execute("SELECT id, title FROM notes ORDER BY id").fetchall()
        return jsonify([dict(row) for row in rows])

    @app.get("/notes/<int:note_id>")  # <int:...> rejects non-numeric IDs with a 404
    def get_note(note_id: int) -> Any:
        # Parameterised query: user input is never concatenated into SQL.
        row = get_db().execute("SELECT id, title, body FROM notes WHERE id = ?", (note_id,)).fetchone()
        return jsonify(dict(row)) if row else error("not found", 404)

    @app.post("/notes")
    def create_note() -> Any:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return error("expected a JSON object", 400)
        title, body = data.get("title"), data.get("body")
        # Allow-list validation: correct types, non-empty, bounded length.
        if not isinstance(title, str) or not title.strip() or len(title) > MAX_TITLE:
            return error(f"title must be a non-empty string of at most {MAX_TITLE} characters", 400)
        if not isinstance(body, str) or len(body) > MAX_BODY:
            return error(f"body must be a string of at most {MAX_BODY} characters", 400)
        db = get_db()
        cursor = db.execute("INSERT INTO notes (title, body) VALUES (?, ?)", (title.strip(), body))
        db.commit()
        return jsonify({"id": cursor.lastrowid, "title": title.strip()}), 201

    return app


if __name__ == "__main__":
    # Local/CI use only. Debug stays off; production would run behind a WSGI server.
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
