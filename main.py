from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse
import os
import json

app = FastAPI()

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")

@app.get("/")
async def root():
    return {"ok": True, "message": "service is running"}

@app.post("/init_project")
async def init_project(
    request: Request,
    x_token: str | None = Header(default=None),
    x_source: str | None = Header(default=None),
):
    if WEBHOOK_SECRET and x_token != WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="invalid token")

    raw_bytes = await request.body()
    raw_text = raw_bytes.decode("utf-8", errors="replace")

    print("====== received /init_project ======")
    print("x_source =", x_source)
    print("content-type =", request.headers.get("content-type"))
    print("raw body:")
    print(raw_text)

    try:
        body = json.loads(raw_text)
    except Exception as e:
        print("JSON parse error:", repr(e))
        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "error": "invalid_json",
                "raw_body": raw_text,
            },
        )

    print("parsed json:")
    print(json.dumps(body, ensure_ascii=False, indent=2))

    return JSONResponse(
        content={
            "ok": True,
            "message": "request received",
        }
    )