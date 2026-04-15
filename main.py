from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse
import os
import json
import re
import urllib.request

app = FastAPI()

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
FEISHU_APP_ID = os.getenv("FEISHU_APP_ID", "")
FEISHU_APP_SECRET = os.getenv("FEISHU_APP_SECRET", "")


@app.get("/")
async def root():
    return {"ok": True, "message": "service is running"}


def parse_loose_feishu_body(raw_text):
    result = {}

    for line in raw_text.splitlines():
        line = line.strip()

        if not line or line == "{" or line == "}":
            continue

        if line.endswith(","):
            line = line[:-1]

        m = re.match(r'^"([^"]+)"\s*:\s*(.+)$', line)
        if not m:
            continue

        key = m.group(1).strip()
        value = m.group(2).strip()

        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]

        result[key] = value

    if not result:
        raise ValueError("cannot parse loose feishu body")

    return result


def get_feishu_tenant_access_token():
    if not FEISHU_APP_ID or not FEISHU_APP_SECRET:
        raise RuntimeError("FEISHU_APP_ID or FEISHU_APP_SECRET is missing")

    url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
    payload = json.dumps({
        "app_id": FEISHU_APP_ID,
        "app_secret": FEISHU_APP_SECRET
    }).encode("utf-8")

    req = urllib.request.Request(
        url=url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode("utf-8")

    data = json.loads(text)

    if data.get("code") != 0:
        raise RuntimeError(f"get tenant_access_token failed: {data}")

    token = data.get("tenant_access_token")
    if not token:
        raise RuntimeError(f"tenant_access_token missing: {data}")

    return token, data


@app.post("/init_project")
async def init_project(
    request: Request,
    x_token: str = Header(default=None),
    x_source: str = Header(default=None)
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

    try:
        tenant_access_token, token_resp = get_feishu_tenant_access_token()
        print("get tenant_access_token success")
        print("token prefix =", tenant_access_token[:20] + "...")
    except Exception as e:
        print("get tenant_access_token failed:", repr(e))
        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "error": "get_tenant_access_token_failed",
                "detail": str(e)
            }
        )

    return JSONResponse(content={
        "ok": True,
        "message": "request received",
        "parsed": body,
        "token_ok": True
    })