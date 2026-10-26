from celery_app import celery_app
import base64, tempfile, os
import scan_core


@celery_app.task(name="tasks.ping")
def ping_task(msg="pong"):
    return {"status": "ok", "msg": msg}


@celery_app.task(bind=True, name="tasks.scan_project")
def scan_project_task(self, username, zip_b64, filename, use_ai=False):
    """Async scan of a ZIP project. Returns findings/score/grade."""
    self.update_state(state="PROGRESS", meta={"stage": "decoding"})
    zip_bytes = base64.b64decode(zip_b64)

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".zip")
    try:
        with os.fdopen(tmp_fd, "wb") as f:
            f.write(zip_bytes)

        self.update_state(state="PROGRESS", meta={"stage": "scanning"})
        findings, score, grade = scan_core.scan_zip(
            username=username,
            zip_path=tmp_path,
            filename=filename,
            use_ai=use_ai,
        )
        return {
            "status": "success",
            "filename": filename,
            "findings": findings,
            "score": score,
            "grade": grade,
            "count": len(findings),
        }
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
