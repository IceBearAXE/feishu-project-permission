import time
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse
import os
import json
import re
import urllib.request
import urllib.error
import urllib.parse
from typing import Any, Dict, List, Optional, Set

app = FastAPI()

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
FEISHU_APP_ID = os.getenv("FEISHU_APP_ID", "")
FEISHU_APP_SECRET = os.getenv("FEISHU_APP_SECRET", "")
BITABLE_APP_TOKEN = os.getenv("BITABLE_APP_TOKEN", "")
BITABLE_TABLE_ID = os.getenv("BITABLE_TABLE_ID", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")
ADMIN_REFRESH_TOKEN = os.getenv("ADMIN_REFRESH_TOKEN", "")
ADMIN_ACCESS_TOKEN_CACHE = ""
ADMIN_ACCESS_TOKEN_EXPIRES_AT = 0
ADMIN_REFRESH_TOKEN_CACHE = ADMIN_REFRESH_TOKEN

# 这里是文档授权用到的常量
# 如果第一次跑授权时报 member_type 不合法，就把这里改掉再试
DRIVE_GROUP_MEMBER_TYPE = "groupid"

# 权限值：view / edit / full_access
PERM_VIEW = "view"
PERM_EDIT = "edit"
PERM_FULL_ACCESS = "full_access"


@app.get("/")
async def root():
    return {"ok": True, "message": "service is running"}

@app.get("/auth/feishu/login")
async def feishu_login():
    try:
        url = build_feishu_admin_login_url()
        return JSONResponse({
            "ok": True,
            "login_url": url,
            "message": "请用固定管理员账号打开 login_url 完成授权"
        })
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": "build_login_url_failed", "detail": str(e)}
        )


@app.get("/auth/feishu/callback")
async def feishu_callback(code: str = "", state: str = ""):
    if not code:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "code is empty"}
        )

    try:
        tokens = exchange_code_for_user_tokens(code)
        print("admin oauth callback success")
        print("admin access token prefix =", tokens["access_token"][:20] + "...")
        print("admin refresh token prefix =", tokens["refresh_token"][:20] + "..." if tokens["refresh_token"] else "")

        return JSONResponse({
            "ok": True,
            "message": "请把 refresh_token 复制到 Render 环境变量 ADMIN_REFRESH_TOKEN，然后重新部署",
            "access_token_prefix": tokens["access_token"][:20] + "...",
            "refresh_token": tokens["refresh_token"]
        })
    except Exception as e:
        print("admin oauth callback failed:", repr(e))
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": "exchange_code_failed", "detail": str(e)}
        )


def parse_loose_feishu_body(raw_text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}

    for line in raw_text.splitlines():
        line = line.strip()

        if not line or line in ("{", "}"):
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


def http_json_request(
    url: str,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    tenant_access_token: Optional[str] = None,
) -> Dict[str, Any]:
    headers: Dict[str, str] = {}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    else:
        data = None

    if tenant_access_token:
        headers["Authorization"] = f"Bearer {tenant_access_token}"

    req = urllib.request.Request(
        url=url,
        data=data,
        headers=headers,
        method=method
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode("utf-8")
            return json.loads(text)
    except urllib.error.HTTPError as e:
        err_text = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTPError {e.code}: {err_text}") from e


def get_feishu_tenant_access_token() -> str:
    if not FEISHU_APP_ID or not FEISHU_APP_SECRET:
        raise RuntimeError("FEISHU_APP_ID or FEISHU_APP_SECRET is missing")

    url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
    payload = {
        "app_id": FEISHU_APP_ID,
        "app_secret": FEISHU_APP_SECRET
    }

    result = http_json_request(url=url, method="POST", payload=payload)

    if result.get("code") != 0:
        raise RuntimeError(f"get tenant_access_token failed: {result}")

    token = result.get("tenant_access_token")
    if not token:
        raise RuntimeError(f"tenant_access_token missing: {result}")

    return token

def get_feishu_app_access_token() -> str:
    if not FEISHU_APP_ID or not FEISHU_APP_SECRET:
        raise RuntimeError("FEISHU_APP_ID or FEISHU_APP_SECRET is missing")

    url = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal"
    payload = {
        "app_id": FEISHU_APP_ID,
        "app_secret": FEISHU_APP_SECRET
    }

    result = http_json_request(url=url, method="POST", payload=payload)

    if result.get("code") != 0:
        raise RuntimeError(f"get app_access_token failed: {result}")

    token = result.get("app_access_token")
    if not token:
        raise RuntimeError(f"app_access_token missing: {result}")

    return token

def build_feishu_admin_login_url() -> str:
    if not FEISHU_APP_ID:
        raise RuntimeError("FEISHU_APP_ID is missing")
    if not APP_BASE_URL:
        raise RuntimeError("APP_BASE_URL is missing")

    redirect_uri = f"{APP_BASE_URL}/auth/feishu/callback"
    encoded_redirect = urllib.parse.quote(redirect_uri, safe="")

    # 这里只保留 offline_access
    scope_str = urllib.parse.quote("offline_access", safe="")

    return (
        "https://open.feishu.cn/open-apis/authen/v1/authorize"
        f"?app_id={FEISHU_APP_ID}"
        f"&redirect_uri={encoded_redirect}"
        f"&scope={scope_str}"
    )


def _extract_oauth_tokens(result: Dict[str, Any]) -> Dict[str, Any]:
    data = result.get("data", {}) if isinstance(result.get("data"), dict) else {}

    access_token = (
        data.get("access_token")
        or data.get("user_access_token")
        or result.get("access_token")
        or result.get("user_access_token")
        or ""
    )
    refresh_token = (
        data.get("refresh_token")
        or result.get("refresh_token")
        or ""
    )
    expires_in = (
        data.get("expires_in")
        or result.get("expires_in")
        or 7200
    )

    return {
        "access_token": str(access_token).strip(),
        "refresh_token": str(refresh_token).strip(),
        "expires_in": int(expires_in),
    }


def exchange_code_for_user_tokens(code: str) -> Dict[str, str]:
    if not code:
        raise RuntimeError("code is empty")

    app_access_token = get_feishu_app_access_token()

    url = "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token"
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "app_access_token": app_access_token
    }

    result = http_json_request(url=url, method="POST", payload=payload)

    if result.get("code") not in (0, None):
        raise RuntimeError(f"exchange code failed: {result}")

    tokens = _extract_oauth_tokens(result)
    if not tokens["access_token"]:
        raise RuntimeError(f"user access token missing: {result}")

    return tokens


def refresh_user_access_token(refresh_token: str) -> Dict[str, str]:
    if not refresh_token:
        raise RuntimeError("refresh_token is empty")

    app_access_token = get_feishu_app_access_token()

    url = "https://open.feishu.cn/open-apis/authen/v1/oidc/refresh_access_token"
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "app_access_token": app_access_token
    }

    result = http_json_request(url=url, method="POST", payload=payload)

    if result.get("code") not in (0, None):
        raise RuntimeError(f"refresh user access token failed: {result}")

    tokens = _extract_oauth_tokens(result)
    if not tokens["access_token"]:
        raise RuntimeError(f"refreshed access token missing: {result}")

    return tokens


def get_admin_user_access_token() -> str:
    global ADMIN_ACCESS_TOKEN_CACHE
    global ADMIN_ACCESS_TOKEN_EXPIRES_AT
    global ADMIN_REFRESH_TOKEN_CACHE

    now = time.time()

    # access_token 还没过期，就直接用，不要反复刷新
    if ADMIN_ACCESS_TOKEN_CACHE and now < ADMIN_ACCESS_TOKEN_EXPIRES_AT - 300:
        return ADMIN_ACCESS_TOKEN_CACHE

    if not ADMIN_REFRESH_TOKEN_CACHE:
        raise RuntimeError("ADMIN_REFRESH_TOKEN is missing")

    tokens = refresh_user_access_token(ADMIN_REFRESH_TOKEN_CACHE)

    ADMIN_ACCESS_TOKEN_CACHE = tokens["access_token"]
    ADMIN_ACCESS_TOKEN_EXPIRES_AT = now + int(tokens.get("expires_in", 7200))

    # 关键：刷新后 refresh_token 会轮换，要更新内存里的值
    if tokens.get("refresh_token"):
        ADMIN_REFRESH_TOKEN_CACHE = tokens["refresh_token"]
        print("admin refresh_token rotated in memory")

    return ADMIN_ACCESS_TOKEN_CACHE


def create_user_group(tenant_access_token: str, group_name: str, description: str = "") -> Dict[str, Any]:
    url = "https://open.feishu.cn/open-apis/contact/v3/group"
    payload = {
        "name": group_name,
        "description": description
    }

    result = http_json_request(
        url=url,
        method="POST",
        payload=payload,
        tenant_access_token=tenant_access_token
    )

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


def update_bitable_record(tenant_access_token: str, record_id: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    if not BITABLE_APP_TOKEN or not BITABLE_TABLE_ID:
        raise RuntimeError("BITABLE_APP_TOKEN or BITABLE_TABLE_ID is missing")

    url = (
        f"https://open.feishu.cn/open-apis/bitable/v1/apps/{BITABLE_APP_TOKEN}"
        f"/tables/{BITABLE_TABLE_ID}/records/{record_id}"
    )

    payload = {"fields": fields}

    result = http_json_request(
        url=url,
        method="PUT",
        payload=payload,
        tenant_access_token=tenant_access_token
    )

    if result.get("code") != 0:
        raise RuntimeError(f"update bitable record failed: {result}")

    return result


def get_bitable_record(tenant_access_token: str, record_id: str) -> Dict[str, Any]:
    if not BITABLE_APP_TOKEN or not BITABLE_TABLE_ID:
        raise RuntimeError("BITABLE_APP_TOKEN or BITABLE_TABLE_ID is missing")

    url = (
        f"https://open.feishu.cn/open-apis/bitable/v1/apps/{BITABLE_APP_TOKEN}"
        f"/tables/{BITABLE_TABLE_ID}/records/{record_id}"
    )

    result = http_json_request(
        url=url,
        method="GET",
        tenant_access_token=tenant_access_token
    )

    if result.get("code") != 0:
        raise RuntimeError(f"get bitable record failed: {result}")

    return result


def normalize_text_to_list(value: Any) -> List[str]:
    """
    支持：
    1. 多行文本，一行一个链接
    2. 字面量 \\n
    3. 分号分隔
    4. 逗号分隔
    """
    if value is None:
        return []

    if isinstance(value, dict):
        maybe_link = str(value.get("link", "")).strip()
        return [maybe_link] if maybe_link else []

    text = str(value).strip()
    if not text:
        return []

    text = text.replace("\\n", "\n")
    text = text.replace("；", ";").replace("，", ",")

    parts: List[str] = []

    for block in text.splitlines():
        block = block.strip()
        if not block:
            continue

        tmp = re.split(r"[;,]", block)
        for item in tmp:
            item = item.strip()
            if item:
                parts.append(item)

    return parts


def extract_link_from_hyperlink_field(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, dict):
        return str(value.get("link", "")).strip()

    return str(value).strip()


def extract_drive_token_from_link(link: str) -> str:
    if not link:
        return ""

    patterns = [
        r"/folder/([A-Za-z0-9]+)",
        r"/file/([A-Za-z0-9]+)",
        r"/docx/([A-Za-z0-9]+)",
        r"/sheet/([A-Za-z0-9]+)",
        r"/wiki/([A-Za-z0-9]+)",
        r"[?&]token=([A-Za-z0-9]+)",
    ]

    for p in patterns:
        m = re.search(p, link)
        if m:
            return m.group(1)

    return ""


def extract_tokens_from_links_field(value: Any) -> List[str]:
    links = normalize_text_to_list(value)
    tokens: List[str] = []

    for link in links:
        token = extract_drive_token_from_link(link)
        if token:
            tokens.append(token)

    seen: Set[str] = set()
    result: List[str] = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            result.append(t)

    return result


def extract_open_ids(field_value: Any) -> List[str]:
    if not field_value:
        return []

    if not isinstance(field_value, list):
        return []

    result: List[str] = []
    for item in field_value:
        if isinstance(item, dict):
            member_id = str(item.get("id", "")).strip()
            if member_id:
                result.append(member_id)

    return result


def list_group_member_open_ids(tenant_access_token: str, group_id: str) -> List[str]:
    member_ids: List[str] = []
    page_token = ""

    while True:
        url = (
            f"https://open.feishu.cn/open-apis/contact/v3/group/{group_id}/member/simplelist"
            f"?member_type=user&member_id_type=open_id&page_size=100"
        )
        if page_token:
            url += f"&page_token={page_token}"

        result = http_json_request(
            url=url,
            method="GET",
            tenant_access_token=tenant_access_token
        )

        if result.get("code") != 0:
            raise RuntimeError(f"list group members failed: {result}")

        data = result.get("data", {})
        items = data.get("items", [])

        for item in items:
            if isinstance(item, dict):
                member_id = str(item.get("member_id", "")).strip()
                if member_id:
                    member_ids.append(member_id)

        if not data.get("has_more"):
            break

        page_token = str(data.get("page_token", "")).strip()
        if not page_token:
            break

    return member_ids


def add_group_member(tenant_access_token: str, group_id: str, open_id: str) -> Dict[str, Any]:
    url = f"https://open.feishu.cn/open-apis/contact/v3/group/{group_id}/member/add"
    payload = {
        "member_type": "user",
        "member_id_type": "open_id",
        "member_id": open_id
    }

    result = http_json_request(
        url=url,
        method="POST",
        payload=payload,
        tenant_access_token=tenant_access_token
    )

    if result.get("code") != 0:
        raise RuntimeError(f"add group member failed: {result}")

    return result


def remove_group_member(tenant_access_token: str, group_id: str, open_id: str) -> Dict[str, Any]:
    url = f"https://open.feishu.cn/open-apis/contact/v3/group/{group_id}/member/remove"
    payload = {
        "member_type": "user",
        "member_id_type": "open_id",
        "member_id": open_id
    }

    result = http_json_request(
        url=url,
        method="POST",
        payload=payload,
        tenant_access_token=tenant_access_token
    )

    if result.get("code") != 0:
        raise RuntimeError(f"remove group member failed: {result}")

    return result


def sync_one_group(
    tenant_access_token: str,
    group_id: str,
    target_open_ids: List[str],
    role_name: str
) -> None:
    current_open_ids = list_group_member_open_ids(tenant_access_token, group_id)

    target_set: Set[str] = set(target_open_ids)
    current_set: Set[str] = set(current_open_ids)

    to_add = sorted(target_set - current_set)
    to_remove = sorted(current_set - target_set)

    print(f"[{role_name}] current =", current_open_ids)
    print(f"[{role_name}] target  =", target_open_ids)
    print(f"[{role_name}] to_add  =", to_add)
    print(f"[{role_name}] to_remove =", to_remove)

    for open_id in to_add:
        add_group_member(tenant_access_token, group_id, open_id)
        print(f"[{role_name}] added:", open_id)

    for open_id in to_remove:
        remove_group_member(tenant_access_token, group_id, open_id)
        print(f"[{role_name}] removed:", open_id)


def get_drive_type_from_token(token: str) -> str:
    """
    根据 token 前缀推断云文档类型
    """
    if not token:
        return ""

    if token.startswith("fld"):
        return "folder"
    if token.startswith("box"):
        return "file"
    if token.startswith("dox"):
        return "docx"
    if token.startswith("sht"):
        return "sheet"
    if token.startswith("wik"):
        return "wiki"

    return "folder"


def create_drive_permission_member(
    tenant_access_token: str,
    token: str,
    file_type: str,
    member_id: str,
    perm: str
) -> Dict[str, Any]:
    url = (
        f"https://open.feishu.cn/open-apis/drive/v1/permissions/{token}/members"
        f"?type={urllib.parse.quote(file_type)}"
    )
    payload = {
        "member_id": member_id,
        "member_type": DRIVE_GROUP_MEMBER_TYPE,
        "perm": perm
    }

    result = http_json_request(
        url=url,
        method="POST",
        payload=payload,
        tenant_access_token=tenant_access_token
    )

    if result.get("code") != 0:
        raise RuntimeError(f"create drive permission member failed: {result}")

    return result


def update_drive_permission_member(
    tenant_access_token: str,
    token: str,
    file_type: str,
    member_id: str,
    perm: str
) -> Dict[str, Any]:
    url = (
        f"https://open.feishu.cn/open-apis/drive/v1/permissions/{token}/members/"
        f"{urllib.parse.quote(member_id)}?type={urllib.parse.quote(file_type)}"
    )
    payload = {
        "member_type": DRIVE_GROUP_MEMBER_TYPE,
        "perm": perm
    }

    result = http_json_request(
        url=url,
        method="PUT",
        payload=payload,
        tenant_access_token=tenant_access_token
    )

    if result.get("code") != 0:
        raise RuntimeError(f"update drive permission member failed: {result}")

    return result


def upsert_drive_group_permission(
    tenant_access_token: str,
    token: str,
    member_group_id: str,
    perm: str
) -> None:
    file_type = get_drive_type_from_token(token)
    if not file_type:
        raise RuntimeError(f"cannot infer file type from token: {token}")

    try:
        result = create_drive_permission_member(
            tenant_access_token=tenant_access_token,
            token=token,
            file_type=file_type,
            member_id=member_group_id,
            perm=perm
        )
        print("create permission success:", token, member_group_id, perm)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    except Exception as e:
        err = str(e)
        print("create permission failed, try update:", err)

        # 如果已经有权限成员，则改为 update
        duplicate_signs = [
            "already",
            "exists",
            "duplicate",
            "重复",
            "已存在"
        ]
        if any(s in err.lower() for s in ["already", "exists", "duplicate"]) or any(s in err for s in ["重复", "已存在"]):
            result = update_drive_permission_member(
                tenant_access_token=tenant_access_token,
                token=token,
                file_type=file_type,
                member_id=member_group_id,
                perm=perm
            )
            print("update permission success:", token, member_group_id, perm)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return

        raise


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

    record_id = str(body.get("record_id", "")).strip()
    project_name = str(body.get("project_name", "")).strip()

    folder_token = str(body.get("folder_token", "")).strip()
    folder_link = str(body.get("folder_link", "")).strip()
    student_links = body.get("student_links", "")
    external_links = body.get("external_links", "")

    extracted_main_token = extract_drive_token_from_link(folder_link) if folder_link else ""
    main_folder_token = extracted_main_token or folder_token

    student_tokens = extract_tokens_from_links_field(student_links)
    external_tokens = extract_tokens_from_links_field(external_links)

    print("project_name =", project_name)
    print("folder_token(from body) =", folder_token)
    print("folder_link =", folder_link)
    print("main_folder_token =", main_folder_token)
    print("student_tokens =", student_tokens)
    print("external_tokens =", external_tokens)

    if not record_id:
        return JSONResponse(status_code=400, content={"ok": False, "error": "record_id is empty"})

    if not project_name:
        return JSONResponse(status_code=400, content={"ok": False, "error": "project_name is empty"})

    try:
        tenant_access_token = get_feishu_tenant_access_token()
        print("get tenant_access_token success")
        print("token prefix =", tenant_access_token[:20] + "...")
    except Exception as e:
        print("get tenant_access_token failed:", repr(e))
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": "get_tenant_access_token_failed", "detail": str(e)}
        )

    try:
        record_result = get_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id
        )
        current_fields = record_result["data"]["record"]["fields"]
    except Exception as e:
        print("get current bitable record failed:", repr(e))
        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "error": "get_current_record_failed",
                "detail": str(e),
                "record_id": record_id
            }
        )

    existing_group_ids = [
        str(current_fields.get("负责人组ID", "")).strip(),
        str(current_fields.get("员工组ID", "")).strip(),
        str(current_fields.get("学生组ID", "")).strip(),
        str(current_fields.get("总体单位ID", "")).strip(),
    ]

    created_groups: List[Dict[str, Any]] = []

    if all(existing_group_ids):
        print("group ids already exist, skip create groups")
        created_groups = [
            {"name": f"{project_name}-项目负责人", "group_id": existing_group_ids[0]},
            {"name": f"{project_name}-员工", "group_id": existing_group_ids[1]},
            {"name": f"{project_name}-学生", "group_id": existing_group_ids[2]},
            {"name": f"{project_name}-总体单位", "group_id": existing_group_ids[3]},
        ]
    else:
        group_names = [
            f"{project_name}-项目负责人",
            f"{project_name}-员工",
            f"{project_name}-学生",
            f"{project_name}-总体单位",
        ]

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

    fields_to_update = {
        "负责人组ID": created_groups[0]["group_id"],
        "员工组ID": created_groups[1]["group_id"],
        "学生组ID": created_groups[2]["group_id"],
        "总体单位ID": created_groups[3]["group_id"],
        "初始化状态": "成功",
        "授权状态": "处理中",
        "授权错误信息": ""
    }

    try:
        update_result = update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields=fields_to_update
        )
        print("update bitable record success")
        print(json.dumps(update_result, ensure_ascii=False, indent=2))
    except Exception as e:
        print("update bitable record failed:", repr(e))
        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "error": "update_bitable_record_failed",
                "detail": str(e),
                "record_id": record_id,
                "created_groups": created_groups
            }
        )

    try:
        if not main_folder_token:
            raise RuntimeError("总文件夹 token 为空，请检查总文件夹链接或文件夹token字段")

        leader_group_id = created_groups[0]["group_id"]
        staff_group_id = created_groups[1]["group_id"]
        student_group_id = created_groups[2]["group_id"]
        external_group_id = created_groups[3]["group_id"]

        print("start real authorization")
        print("leader group id =", leader_group_id)
        print("staff group id  =", staff_group_id)
        print("student group id =", student_group_id)
        print("external group id =", external_group_id)
        print("main folder token =", main_folder_token)
        print("student tokens =", student_tokens)
        print("external tokens =", external_tokens)
        drive_access_token = get_admin_user_access_token()
        print("got admin user_access_token for drive authorization")

        # 总文件夹
        upsert_drive_group_permission(
            tenant_access_token=drive_access_token,
            token=main_folder_token,
            member_group_id=leader_group_id,
            perm=PERM_FULL_ACCESS
        )
        upsert_drive_group_permission(
            tenant_access_token=drive_access_token,
            token=main_folder_token,
            member_group_id=staff_group_id,
            perm=PERM_EDIT
        )

        # 学生链接列表
        for token in student_tokens:
            upsert_drive_group_permission(
                tenant_access_token=drive_access_token,
                token=token,
                member_group_id=student_group_id,
                perm=PERM_EDIT
            )

        # 总体单位链接列表
        for token in external_tokens:
            upsert_drive_group_permission(
                tenant_access_token=drive_access_token,
                token=token,
                member_group_id=external_group_id,
                perm=PERM_VIEW
            )

        update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields={
                "授权状态": "成功",
                "授权错误信息": ""
            }
        )
        print("authorization success")
    except Exception as e:
        print("authorization failed:", repr(e))
        try:
            update_bitable_record(
                tenant_access_token=tenant_access_token,
                record_id=record_id,
                fields={
                    "授权状态": "失败",
                    "授权错误信息": str(e)
                }
            )
        except Exception as e2:
            print("write auth error back failed:", repr(e2))

        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "error": "authorization_failed",
                "detail": str(e),
                "record_id": record_id
            }
        )

    return JSONResponse(
        content={
            "ok": True,
            "message": "groups ready and authorization completed",
            "record_id": record_id,
            "project_name": project_name,
            "main_folder_token": main_folder_token,
            "student_tokens": student_tokens,
            "external_tokens": external_tokens,
            "groups": created_groups
        }
    )


@app.post("/sync_members")
async def sync_members(
    request: Request,
    x_token: str = Header(default=None),
    x_source: str = Header(default=None)
):
    if WEBHOOK_SECRET and x_token != WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="invalid token")

    raw_bytes = await request.body()
    raw_text = raw_bytes.decode("utf-8", errors="replace")

    print("====== received /sync_members ======")
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

    record_id = str(body.get("record_id", "")).strip()
    if not record_id:
        return JSONResponse(status_code=400, content={"ok": False, "error": "record_id is empty"})

    try:
        tenant_access_token = get_feishu_tenant_access_token()
        print("get tenant_access_token success")
        print("token prefix =", tenant_access_token[:20] + "...")
    except Exception as e:
        print("get tenant_access_token failed:", repr(e))
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": "get_tenant_access_token_failed", "detail": str(e)}
        )

    try:
        record_result = get_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id
        )
        print("get bitable record success")
        print(json.dumps(record_result, ensure_ascii=False, indent=2))
    except Exception as e:
        print("get bitable record failed:", repr(e))
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": "get_bitable_record_failed", "detail": str(e), "record_id": record_id}
        )

    fields = record_result["data"]["record"]["fields"]

    role_config = [
        ("项目负责人", "负责人组ID"),
        ("员工", "员工组ID"),
        ("学生", "学生组ID"),
        ("总体单位", "总体单位ID"),
    ]

    try:
        for role_field, group_id_field in role_config:
            group_id = str(fields.get(group_id_field, "")).strip()
            if not group_id:
                print(f"[{role_field}] skip, group_id is empty")
                continue

            target_open_ids = extract_open_ids(fields.get(role_field))
            sync_one_group(
                tenant_access_token=tenant_access_token,
                group_id=group_id,
                target_open_ids=target_open_ids,
                role_name=role_field
            )

        update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields={
                "同步状态": "成功",
                "同步错误信息": ""
            }
        )
        print("sync members success")
    except Exception as e:
        print("sync members failed:", repr(e))
        try:
            update_bitable_record(
                tenant_access_token=tenant_access_token,
                record_id=record_id,
                fields={
                    "同步状态": "失败",
                    "同步错误信息": str(e)
                }
            )
        except Exception as e2:
            print("write sync error back failed:", repr(e2))

        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": "sync_members_failed", "detail": str(e), "record_id": record_id}
        )

    return JSONResponse(
        content={"ok": True, "message": "members synced", "record_id": record_id}
    )