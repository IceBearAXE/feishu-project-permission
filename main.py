from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse
import os
import json
import re

app = FastAPI()

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")

@app.get("/")
async def root():
    return {"ok": True, "message": "service is running"}

def parse_loose_feishu_body(raw_text: str) -> dict:
    """
    兼容飞书自动化发来的这种 body：
    {
      "project_code": AUTO-TEST-005,
      "project_name": AUTO-TEST-005,
      "folder_token": TOKEN-AUTO-006
    }
    """
    result = {}

    for line in raw_text.splitlines():
        line = line.strip()

        if not line or line in ("{", "}"):
            continue

        # 去掉行尾逗号
        if line.endswith(","):
            line = line[:-1]

        m = re.match(r'^"([^"]+)"\s*:\s*(.+)$', line)
        if not m:
            continue

        key = m.group(1).strip()
        value = m.group(2).strip()

        # 如果值本来带引号，就去掉最外层引号
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]

        result[key] = value

    if not result:
        raise ValueError("cannot parse loose feishu body")

    return result

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
        print("parsed by normal json.loads")
    except Exception as e:
        print("JSON parse error:", repr(e))
        body = parse_loose_feishu_body(raw_text)
        print("parsed by loose parser")

    print("parsed body:")
    print(json.dumps(body, ensure_ascii=False, indent=2))

    return JSONResponse(
        content={
            "ok": True,
            "message": "request received",
            "parsed": body,
        }
    )