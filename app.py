#!/usr/bin/env python3
"""app.py — (선택) FastAPI 라이브 데모.

브라우저에서 취약 vs 방어 결과를 JSON으로 확인. 실제 디스코드와 무관(샌드박스).

실행:
    pip install fastapi uvicorn
    python app.py            # http://127.0.0.1:8000
"""

from __future__ import annotations

from dataclasses import asdict

try:
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse
    import uvicorn
except ImportError:  # pragma: no cover
    raise SystemExit("pip install fastapi uvicorn 후 실행하세요.")

from scamlab.scenarios import compare

app = FastAPI(title="scamlab", description="Discord 계정 탈취 스캠 샌드박스")


@app.get("/", response_class=HTMLResponse)
def index():
    return """
    <h2>scamlab — Discord 계정 탈취 스캠 샌드박스</h2>
    <p>실제 디스코드와 무관한 메모리 시뮬레이션입니다.</p>
    <ul>
      <li><a href="/api/compare?entry=token_grabber">/api/compare?entry=token_grabber</a></li>
      <li><a href="/api/compare?entry=qr_login">/api/compare?entry=qr_login</a></li>
      <li><a href="/api/compare?entry=oauth_phish">/api/compare?entry=oauth_phish</a></li>
    </ul>
    """


@app.get("/api/compare")
def api_compare(entry: str = "token_grabber"):
    insecure, secure = compare(entry=entry)
    return {"entry": entry, "insecure": asdict(insecure), "secure": asdict(secure)}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
