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


def feishu_post_json(url, payload, tenant_access_token=None):
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    if tenant_access_token:
        headers["Authorization"] = f"Bearer {tenant_access_token}"

    req = urllib.request.Request(
        url=url,
        data=data,
        headers=headers,
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode("utf-8")

    result = json.loads(text)
    return result


def get_feishu_tenant_access_token():
    if not FEISHU_APP_ID or not FEISHU_APP_SECRET:
        raise RuntimeError("FEISHU_APP_ID or FEISHU_APP_SECRET is missing")

    url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
    payload = {
        "app_id": FEISHU_APP_ID,
        "app_secret": FEISHU_APP_SECRET
    }

    result = feishu_post_json(url, payload)

    if result.get("code") != 0:
        raise RuntimeError(f"get tenant_access_token failed: {result}")

    token = result.get("tenant_access_token")
    if not token:
        raise RuntimeError(f"tenant_access_token missing: {result}")

    return token


def create_user_group(tenant_access_token, group_name, description=""):
    url = "https://open.feishu.cn/open-apis/contact/v3/group"
    payload = {
        "name": group_name,
        "description": description
    }

    result = feishu_post_json(url, payload, tenant_access_token)

    if result.get("code") != 0:
        raise RuntimeError(f"create user group failed: {result}")

    data = result.get("data", {})
    group_id = data.get("group_id")
    if not group_id:
        raise RuntimeError(f"group_id missing in response: {result}")

    return {
        "group_id": group_id,
        "raw": result
    }


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

    project_code = body.get("project_code", "").strip()
    project_name = body.get("project_name", "").strip()
    folder_token = body.get("folder_token", "").strip()

    if not project_name:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "project_name is empty"}
        )

    try:
        tenant_access_token = get_feishu_tenant_access_token()
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

    group_names = [
        f"{project_name}-项目负责人",
        f"{project_name}-员工",
        f"{project_name}-学生",
        f"{project_name}-总体单位",
    ]

    created_groups = []

    try:
        for group_name in group_names:
            created = create_user_group(
                tenant_access_token=tenant_access_token,
                group_name=group_name,
                description=f"项目 {project_name} 自动创建的权限用户组"
            )
            created_groups.append({
                "name": group_name,
                "group_id": created["group_id"]
            })
            print("created group:", group_name, "=>", created["group_id"])
    except Exception as e:
        print("create groups failed:", repr(e))
        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "error": "create_groups_failed",
                "detail": str(e),
                "created_groups": created_groups
            }
        )

    return JSONResponse(content={
        "ok": True,
        "message": "groups created",
        "project_code": project_code,
        "project_name": project_name,
        "folder_token": folder_token,
        "groups": created_groups
    })