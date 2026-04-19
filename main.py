import json
import os
import re
import time
import urllib.parse
from typing import Any, Dict, List, Set, Tuple

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

app = FastAPI()

# =========================
# Environment variables
# =========================
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
FEISHU_APP_ID = os.getenv("FEISHU_APP_ID", "")
FEISHU_APP_SECRET = os.getenv("FEISHU_APP_SECRET", "")
BITABLE_APP_TOKEN = os.getenv("BITABLE_APP_TOKEN", "")
BITABLE_TABLE_ID = os.getenv("BITABLE_TABLE_ID", "")
CONFIG_TABLE_ID = os.getenv("CONFIG_TABLE_ID", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")
ADMIN_REFRESH_TOKEN = os.getenv("ADMIN_REFRESH_TOKEN", "")

# =========================
# Runtime cache
# =========================
TENANT_ACCESS_TOKEN_CACHE = ""
TENANT_ACCESS_TOKEN_EXPIRES_AT = 0.0

APP_ACCESS_TOKEN_CACHE = ""
APP_ACCESS_TOKEN_EXPIRES_AT = 0.0

ADMIN_ACCESS_TOKEN_CACHE = ""
ADMIN_ACCESS_TOKEN_EXPIRES_AT = 0.0
ADMIN_REFRESH_TOKEN_CACHE = ""

# =========================
# Field names
# =========================
FIELD_PROJECT_CODE = "项目编号"
FIELD_PROJECT_NAME = "项目名称"
FIELD_PROJECT_STATUS = "项目状态"
FIELD_EXEC_STATUS = "执行状态"
FIELD_ERROR_INFO = "错误信息"

FIELD_MAIN_FOLDER_LINK = "总文件夹链接"
FIELD_STUDENT_LINKS = "学生权限链接列表"
FIELD_EXTERNAL_LINKS = "总体单位权限链接列表"

FIELD_LEADER_MEMBERS = "项目负责人"
FIELD_STAFF_MEMBERS = "员工"
FIELD_STUDENT_MEMBERS = "学生"
FIELD_EXTERNAL_MEMBERS = "总体单位"

FIELD_LEADER_PERM = "负责人权限"
FIELD_STAFF_PERM = "员工权限"
FIELD_STUDENT_PERM = "学生权限"
FIELD_EXTERNAL_PERM = "总体单位权限"

# 旧字段，按人授权方案里不再使用，但保留兼容
FIELD_LEADER_GROUP_ID = "负责人组ID"
FIELD_STAFF_GROUP_ID = "员工组ID"
FIELD_STUDENT_GROUP_ID = "学生组ID"
FIELD_EXTERNAL_GROUP_ID = "总体单位ID"

FIELD_AUTHED_MAIN_TOKEN = "已授权总文件夹token"
FIELD_AUTHED_STUDENT_TOKENS = "已授权学生token列表"
FIELD_AUTHED_EXTERNAL_TOKENS = "已授权总体单位token列表"

FIELD_AUTHED_LEADER_OPEN_IDS = "已授权项目负责人open_id列表"
FIELD_AUTHED_STAFF_OPEN_IDS = "已授权员工open_id列表"
FIELD_AUTHED_STUDENT_OPEN_IDS = "已授权学生open_id列表"
FIELD_AUTHED_EXTERNAL_OPEN_IDS = "已授权总体单位open_id列表"

# =========================
# Permission constants
# =========================
PERM_VIEW = "view"
PERM_EDIT = "edit"
PERM_FULL_ACCESS = "full_access"

# 根据飞书权限接口，用户按 openid 作为 member_type/member_id 传入。
DRIVE_USER_MEMBER_TYPE = "openid"


# =========================
# Basic routes
# =========================
@app.get("/")
async def root():
    return {"ok": True, "message": "service is running"}


@app.get("/health")
async def health():
    return {"ok": True}


# =========================
# Generic helpers
# =========================
def http_json_request(
    url: str,
    method: str = "GET",
    payload: Any = None,
    access_token: str = "",
    extra_headers: Dict[str, str] | None = None,
    timeout: int = 60,
) -> Dict[str, Any]:
    headers: Dict[str, str] = {}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    if payload is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
    if extra_headers:
        headers.update(extra_headers)

    resp = requests.request(
        method=method.upper(),
        url=url,
        headers=headers,
        json=payload,
        timeout=timeout,
    )

    text = resp.text or ""
    try:
        data = resp.json()
    except Exception:
        data = {"raw_text": text}

    if not (200 <= resp.status_code < 300):
        raise RuntimeError(f"HTTPError {resp.status_code}: {data}")

    if not isinstance(data, dict):
        raise RuntimeError(f"unexpected response: {data}")

    return data


def parse_loose_feishu_body(raw_text: str) -> Dict[str, Any]:
    text = (raw_text or "").strip()
    if not text:
        return {}

    fixed = re.sub(
        r'(:\s*)([A-Za-z0-9_\-]+)(\s*[,}])',
        lambda m: f'{m.group(1)}"{m.group(2)}"{m.group(3)}',
        text,
    )
    try:
        obj = json.loads(fixed)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    m = re.search(r'"record_id"\s*:\s*"?(?P<rid>[A-Za-z0-9_\-]+)"?', text)
    if m:
        return {"record_id": m.group("rid")}

    return {}


def normalize_link_field(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("link") or value.get("text") or "").strip()
    return str(value or "").strip()


def collect_urls(value: Any) -> List[str]:
    urls: List[str] = []

    if isinstance(value, dict):
        for k in ["link", "text", "url"]:
            v = value.get(k)
            if isinstance(v, str):
                urls.extend(re.findall(r"https?://[^\s]+", v))
        for v in value.values():
            urls.extend(collect_urls(v))

    elif isinstance(value, list):
        for item in value:
            urls.extend(collect_urls(item))

    elif isinstance(value, str):
        urls.extend(re.findall(r"https?://[^\s]+", value))

    return urls


def extract_drive_token_from_link(link: str) -> str:
    text = str(link or "").strip()
    if not text:
        return ""

    patterns = [
        r"/drive/folder/([A-Za-z0-9]+)",
        r"/docx?/([A-Za-z0-9]+)",
        r"/wiki/([A-Za-z0-9]+)",
        r"/sheets?/([A-Za-z0-9]+)",
    ]
    for p in patterns:
        m = re.search(p, text)
        if m:
            return m.group(1)
    return ""


def extract_tokens_from_links_field(value: Any) -> List[str]:
    tokens: List[str] = []
    urls = collect_urls(value)
    for url in urls:
        token = extract_drive_token_from_link(url)
        if token:
            tokens.append(token)
    return sorted(set(tokens))


def get_drive_type_from_token(token: str) -> str:
    if not token:
        return ""

    if token.startswith("fld"):
        return "folder"
    if token.startswith("box"):
        return "file"
    if token.startswith("doc"):
        return "docx"
    if token.startswith("sht"):
        return "sheet"
    if token.startswith("wik"):
        return "wiki"

    return "folder"


def extract_people_open_ids(value: Any) -> List[str]:
    result: List[str] = []
    if not isinstance(value, list):
        return result

    for item in value:
        if not isinstance(item, dict):
            continue
        open_id = str(item.get("id", "")).strip()
        if open_id:
            result.append(open_id)

    return sorted(set(result))


def parse_persisted_list(value: Any) -> List[str]:
    text = str(value or "").strip()
    if not text:
        return []
    return sorted(set([x.strip() for x in text.splitlines() if x.strip()]))


def serialize_list(items: List[str]) -> str:
    return "\n".join(sorted(set([str(x).strip() for x in items if str(x).strip()])))


def get_current_project_tokens(fields: Dict[str, Any]) -> Dict[str, Any]:
    main_link = normalize_link_field(fields.get(FIELD_MAIN_FOLDER_LINK))
    main_token = extract_drive_token_from_link(main_link)

    student_tokens = extract_tokens_from_links_field(fields.get(FIELD_STUDENT_LINKS, ""))
    external_tokens = extract_tokens_from_links_field(fields.get(FIELD_EXTERNAL_LINKS, ""))

    return {
        "main_token": main_token,
        "student_tokens": student_tokens,
        "external_tokens": external_tokens,
    }


def get_current_project_people(fields: Dict[str, Any]) -> Dict[str, List[str]]:
    return {
        "leader_open_ids": extract_people_open_ids(fields.get(FIELD_LEADER_MEMBERS, [])),
        "staff_open_ids": extract_people_open_ids(fields.get(FIELD_STAFF_MEMBERS, [])),
        "student_open_ids": extract_people_open_ids(fields.get(FIELD_STUDENT_MEMBERS, [])),
        "external_open_ids": extract_people_open_ids(fields.get(FIELD_EXTERNAL_MEMBERS, [])),
    }

def normalize_role_perm(value: Any, default_perm: str) -> str:
    text = str(value or "").strip()

    mapping = {
        "查看": PERM_VIEW,
        "阅读": PERM_VIEW,
        "view": PERM_VIEW,
        "read": PERM_VIEW,

        "编辑": PERM_EDIT,
        "edit": PERM_EDIT,

        "管理": PERM_FULL_ACCESS,
        "full_access": PERM_FULL_ACCESS,
        "manage": PERM_FULL_ACCESS,
    }

    if not text:
        return default_perm

    return mapping.get(text, default_perm)


def get_current_project_perms(fields: Dict[str, Any]) -> Dict[str, str]:
    return {
        "leader_perm": normalize_role_perm(fields.get(FIELD_LEADER_PERM), PERM_FULL_ACCESS),
        "staff_perm": normalize_role_perm(fields.get(FIELD_STAFF_PERM), PERM_EDIT),
        "student_perm": normalize_role_perm(fields.get(FIELD_STUDENT_PERM), PERM_EDIT),
        "external_perm": normalize_role_perm(fields.get(FIELD_EXTERNAL_PERM), PERM_VIEW),
    }


def get_authed_project_tokens(fields: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "main_token": str(fields.get(FIELD_AUTHED_MAIN_TOKEN, "")).strip(),
        "student_tokens": parse_persisted_list(fields.get(FIELD_AUTHED_STUDENT_TOKENS, "")),
        "external_tokens": parse_persisted_list(fields.get(FIELD_AUTHED_EXTERNAL_TOKENS, "")),
    }


def get_authed_project_people(fields: Dict[str, Any]) -> Dict[str, List[str]]:
    return {
        "leader_open_ids": parse_persisted_list(fields.get(FIELD_AUTHED_LEADER_OPEN_IDS, "")),
        "staff_open_ids": parse_persisted_list(fields.get(FIELD_AUTHED_STAFF_OPEN_IDS, "")),
        "student_open_ids": parse_persisted_list(fields.get(FIELD_AUTHED_STUDENT_OPEN_IDS, "")),
        "external_open_ids": parse_persisted_list(fields.get(FIELD_AUTHED_EXTERNAL_OPEN_IDS, "")),
    }


async def parse_webhook_request(request: Request, route_name: str) -> Dict[str, Any]:
    raw_bytes = await request.body()
    raw_text = raw_bytes.decode("utf-8", errors="replace")

    print(f"====== received {route_name} ======")
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
    return body


# =========================
# Auth helpers
# =========================
def get_feishu_tenant_access_token() -> str:
    global TENANT_ACCESS_TOKEN_CACHE, TENANT_ACCESS_TOKEN_EXPIRES_AT

    now = time.time()
    if TENANT_ACCESS_TOKEN_CACHE and now < TENANT_ACCESS_TOKEN_EXPIRES_AT - 300:
        return TENANT_ACCESS_TOKEN_CACHE

    url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
    payload = {
        "app_id": FEISHU_APP_ID,
        "app_secret": FEISHU_APP_SECRET,
    }

    result = http_json_request(url=url, method="POST", payload=payload)

    if result.get("code") != 0:
        raise RuntimeError(f"get tenant access token failed: {result}")

    TENANT_ACCESS_TOKEN_CACHE = str(result.get("tenant_access_token", "")).strip()
    TENANT_ACCESS_TOKEN_EXPIRES_AT = now + int(result.get("expire", 7200))

    if not TENANT_ACCESS_TOKEN_CACHE:
        raise RuntimeError(f"tenant_access_token missing in response: {result}")

    return TENANT_ACCESS_TOKEN_CACHE


def get_feishu_app_access_token() -> str:
    global APP_ACCESS_TOKEN_CACHE, APP_ACCESS_TOKEN_EXPIRES_AT

    now = time.time()
    if APP_ACCESS_TOKEN_CACHE and now < APP_ACCESS_TOKEN_EXPIRES_AT - 300:
        return APP_ACCESS_TOKEN_CACHE

    url = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal"
    payload = {
        "app_id": FEISHU_APP_ID,
        "app_secret": FEISHU_APP_SECRET,
    }

    result = http_json_request(url=url, method="POST", payload=payload)

    if result.get("code") != 0:
        raise RuntimeError(f"get app access token failed: {result}")

    APP_ACCESS_TOKEN_CACHE = str(result.get("app_access_token", "")).strip()
    APP_ACCESS_TOKEN_EXPIRES_AT = now + int(result.get("expire", 7200))

    if not APP_ACCESS_TOKEN_CACHE:
        raise RuntimeError(f"app_access_token missing in response: {result}")

    return APP_ACCESS_TOKEN_CACHE


def exchange_code_for_user_tokens(code: str) -> Dict[str, Any]:
    app_access_token = get_feishu_app_access_token()
    url = "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token"
    payload = {
        "grant_type": "authorization_code",
        "code": code,
    }

    result = http_json_request(
        url=url,
        method="POST",
        payload=payload,
        access_token=app_access_token,
    )

    if result.get("code") != 0:
        raise RuntimeError(f"exchange code failed: {result}")

    data = result.get("data", {})
    return {
        "access_token": str(data.get("access_token", "")).strip(),
        "refresh_token": str(data.get("refresh_token", "")).strip(),
        "expires_in": int(data.get("expires_in", 7200)),
    }


def refresh_user_access_token(refresh_token: str) -> Dict[str, Any]:
    app_access_token = get_feishu_app_access_token()
    url = "https://open.feishu.cn/open-apis/authen/v1/oidc/refresh_access_token"
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }

    result = http_json_request(
        url=url,
        method="POST",
        payload=payload,
        access_token=app_access_token,
    )

    if result.get("code") != 0:
        raise RuntimeError(f"refresh user access token failed: {result}")

    data = result.get("data", {})
    return {
        "access_token": str(data.get("access_token", "")).strip(),
        "refresh_token": str(data.get("refresh_token", "")).strip(),
        "expires_in": int(data.get("expires_in", 7200)),
    }


@app.get("/auth/feishu/login")
async def feishu_login():
    if not APP_BASE_URL:
        return JSONResponse(status_code=500, content={"ok": False, "error": "APP_BASE_URL is empty"})

    redirect_uri = f"{APP_BASE_URL}/auth/feishu/callback"
    url = (
        "https://open.feishu.cn/open-apis/authen/v1/authorize"
        f"?app_id={urllib.parse.quote(FEISHU_APP_ID)}"
        f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
        f"&state=admin"
    )
    return RedirectResponse(url=url)


@app.get("/auth/feishu/callback")
async def feishu_callback(code: str = "", state: str = ""):
    global ADMIN_REFRESH_TOKEN_CACHE
    global ADMIN_ACCESS_TOKEN_CACHE
    global ADMIN_ACCESS_TOKEN_EXPIRES_AT

    if not code:
        return JSONResponse(status_code=400, content={"ok": False, "error": "code is empty"})

    try:
        tokens = exchange_code_for_user_tokens(code)

        ADMIN_ACCESS_TOKEN_CACHE = tokens["access_token"]
        ADMIN_ACCESS_TOKEN_EXPIRES_AT = time.time() + int(tokens.get("expires_in", 7200))

        if tokens.get("refresh_token"):
            ADMIN_REFRESH_TOKEN_CACHE = tokens["refresh_token"]
            tenant_access_token = get_feishu_tenant_access_token()
            save_persisted_admin_refresh_token(tenant_access_token, tokens["refresh_token"])

        return JSONResponse(
            content={
                "ok": True,
                "message": "管理员 refresh_token 已写入系统配置表",
                "access_token_prefix": tokens["access_token"][:20] + "..." if tokens["access_token"] else "",
            }
        )
    except Exception as e:
        print("admin oauth callback failed:", repr(e))
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": "exchange_code_failed", "detail": str(e)},
        )


def get_admin_user_access_token() -> str:
    global ADMIN_ACCESS_TOKEN_CACHE
    global ADMIN_ACCESS_TOKEN_EXPIRES_AT
    global ADMIN_REFRESH_TOKEN_CACHE

    now = time.time()

    if ADMIN_ACCESS_TOKEN_CACHE and now < ADMIN_ACCESS_TOKEN_EXPIRES_AT - 300:
        return ADMIN_ACCESS_TOKEN_CACHE

    tenant_access_token = get_feishu_tenant_access_token()

    refresh_token = ""

    if ADMIN_REFRESH_TOKEN_CACHE.strip():
        refresh_token = ADMIN_REFRESH_TOKEN_CACHE.strip()
        print("using refresh token from memory cache")
    else:
        persisted_token = get_persisted_admin_refresh_token(tenant_access_token).strip()
        if persisted_token:
            refresh_token = persisted_token
            ADMIN_REFRESH_TOKEN_CACHE = persisted_token
            print("using refresh token from config table")
        elif ADMIN_REFRESH_TOKEN.strip():
            refresh_token = ADMIN_REFRESH_TOKEN.strip()
            ADMIN_REFRESH_TOKEN_CACHE = refresh_token
            print("using refresh token from env fallback")

    if not refresh_token:
        raise RuntimeError("ADMIN_REFRESH_TOKEN is missing")

    tokens = refresh_user_access_token(refresh_token)

    ADMIN_ACCESS_TOKEN_CACHE = tokens["access_token"]
    ADMIN_ACCESS_TOKEN_EXPIRES_AT = now + int(tokens.get("expires_in", 7200))

    if tokens.get("refresh_token"):
        ADMIN_REFRESH_TOKEN_CACHE = tokens["refresh_token"]
        save_persisted_admin_refresh_token(tenant_access_token, tokens["refresh_token"])
        print("admin refresh_token rotated and persisted")

    return ADMIN_ACCESS_TOKEN_CACHE


# =========================
# Bitable helpers
# =========================
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
        access_token=tenant_access_token,
    )

    if result.get("code") != 0:
        raise RuntimeError(f"get bitable record failed: {result}")

    return result


def update_bitable_record(
    tenant_access_token: str,
    record_id: str,
    fields: Dict[str, Any],
) -> Dict[str, Any]:
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
        access_token=tenant_access_token,
    )

    if result.get("code") != 0:
        raise RuntimeError(f"update bitable record failed: {result}")

    return result


def list_bitable_records(tenant_access_token: str, table_id: str, page_size: int = 100) -> Dict[str, Any]:
    if not BITABLE_APP_TOKEN or not table_id:
        raise RuntimeError("BITABLE_APP_TOKEN or table_id is missing")

    url = (
        f"https://open.feishu.cn/open-apis/bitable/v1/apps/{BITABLE_APP_TOKEN}"
        f"/tables/{table_id}/records?page_size={page_size}"
    )

    result = http_json_request(
        url=url,
        method="GET",
        access_token=tenant_access_token,
    )

    if result.get("code") != 0:
        raise RuntimeError(f"list bitable records failed: {result}")

    return result


def update_bitable_record_by_table(
    tenant_access_token: str,
    table_id: str,
    record_id: str,
    fields: Dict[str, Any],
) -> Dict[str, Any]:
    if not BITABLE_APP_TOKEN or not table_id:
        raise RuntimeError("BITABLE_APP_TOKEN or table_id is missing")

    url = (
        f"https://open.feishu.cn/open-apis/bitable/v1/apps/{BITABLE_APP_TOKEN}"
        f"/tables/{table_id}/records/{record_id}"
    )

    payload = {"fields": fields}

    result = http_json_request(
        url=url,
        method="PUT",
        payload=payload,
        access_token=tenant_access_token,
    )

    if result.get("code") != 0:
        raise RuntimeError(f"update bitable record by table failed: {result}")

    return result


def get_persisted_admin_refresh_token(tenant_access_token: str) -> str:
    if not CONFIG_TABLE_ID:
        return ""

    result = list_bitable_records(
        tenant_access_token=tenant_access_token,
        table_id=CONFIG_TABLE_ID,
        page_size=100,
    )

    items = result.get("data", {}).get("items", [])
    for item in items:
        fields = item.get("fields", {})
        key = str(fields.get("配置项", "")).strip()
        if key == "ADMIN_REFRESH_TOKEN":
            return str(fields.get("配置值", "")).strip()

    return ""


def save_persisted_admin_refresh_token(tenant_access_token: str, refresh_token: str) -> None:
    if not CONFIG_TABLE_ID:
        print("CONFIG_TABLE_ID is empty, skip persist refresh token")
        return

    result = list_bitable_records(
        tenant_access_token=tenant_access_token,
        table_id=CONFIG_TABLE_ID,
        page_size=100,
    )

    items = result.get("data", {}).get("items", [])
    for item in items:
        fields = item.get("fields", {})
        key = str(fields.get("配置项", "")).strip()
        if key == "ADMIN_REFRESH_TOKEN":
            record_id = item.get("record_id") or item.get("id")
            if not record_id:
                raise RuntimeError("config record_id is missing")

            update_bitable_record_by_table(
                tenant_access_token=tenant_access_token,
                table_id=CONFIG_TABLE_ID,
                record_id=record_id,
                fields={"配置值": refresh_token},
            )
            print("persisted admin refresh token to config table")
            return

    raise RuntimeError("ADMIN_REFRESH_TOKEN row not found in config table")


# =========================
# Direct permission helpers (person-based)
# =========================
def create_drive_permission_member(
    access_token: str,
    token: str,
    file_type: str,
    member_id: str,
    member_type: str,
    perm: str,
) -> Dict[str, Any]:
    url = (
        f"https://open.feishu.cn/open-apis/drive/v1/permissions/{token}/members"
        f"?type={urllib.parse.quote(file_type)}"
    )

    payload = {
        "member_id": member_id,
        "member_type": member_type,
        "perm": perm,
    }

    result = http_json_request(
        url=url,
        method="POST",
        payload=payload,
        access_token=access_token,
    )

    if result.get("code") != 0:
        raise RuntimeError(f"create drive permission member failed: {result}")

    return result


def update_drive_permission_member(
    access_token: str,
    token: str,
    file_type: str,
    member_id: str,
    member_type: str,
    perm: str,
) -> Dict[str, Any]:
    url = (
        f"https://open.feishu.cn/open-apis/drive/v1/permissions/{token}/members/"
        f"{urllib.parse.quote(member_id)}?type={urllib.parse.quote(file_type)}"
    )

    payload = {
        "member_type": member_type,
        "perm": perm,
    }

    result = http_json_request(
        url=url,
        method="PUT",
        payload=payload,
        access_token=access_token,
    )

    if result.get("code") != 0:
        raise RuntimeError(f"update drive permission member failed: {result}")

    return result


def upsert_drive_user_permission(
    access_token: str,
    token: str,
    member_open_id: str,
    perm: str,
) -> None:
    file_type = get_drive_type_from_token(token)
    if not file_type:
        raise RuntimeError(f"cannot infer file type from token: {token}")

    # 关键改动：不再先 create 再猜要不要 update
    # 直接先删旧权限，再按新权限重建
    safe_remove_drive_user_permission(access_token, token, member_open_id)

    # 给飞书一点点时间处理删除
    time.sleep(0.2)

    result = create_drive_permission_member(
        access_token=access_token,
        token=token,
        file_type=file_type,
        member_id=member_open_id,
        member_type=DRIVE_USER_MEMBER_TYPE,
        perm=perm,
    )
    print("replace permission success:", token, member_open_id, perm)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def delete_drive_permission_member(
    access_token: str,
    token: str,
    member_id: str,
    member_type: str,
) -> Dict[str, Any]:
    file_type = get_drive_type_from_token(token)
    if not file_type:
        raise RuntimeError(f"cannot infer file type from token: {token}")

    url = (
        f"https://open.feishu.cn/open-apis/drive/v1/permissions/{token}/members/"
        f"{urllib.parse.quote(member_id)}"
        f"?type={urllib.parse.quote(file_type)}"
        f"&member_type={urllib.parse.quote(member_type)}"
    )

    result = http_json_request(
        url=url,
        method="DELETE",
        access_token=access_token,
    )

    if result.get("code") != 0:
        raise RuntimeError(f"delete drive permission member failed: {result}")

    return result

def safe_remove_drive_permission_member(
    access_token: str,
    token: str,
    member_id: str,
    member_type: str,
) -> None:
    if not token or not member_id or not member_type:
        return

    try:
        result = delete_drive_permission_member(
            access_token=access_token,
            token=token,
            member_id=member_id,
            member_type=member_type,
        )
        print("delete permission success:", token, member_type, member_id)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as e:
        err = str(e)
        if "404" in err or "not found" in err.lower() or "不存在" in err:
            print("delete permission skipped, already gone:", token, member_type, member_id)
            return
        raise


def list_drive_permission_members(
    access_token: str,
    token: str,
    page_size: int = 200,
) -> List[Dict[str, Any]]:
    file_type = get_drive_type_from_token(token)
    if not file_type:
        raise RuntimeError(f"cannot infer file type from token: {token}")

    url = "https://open.feishu.cn/open-apis/drive/permission/member/list"

    all_items: List[Dict[str, Any]] = []
    page_token = ""

    while True:
        payload: Dict[str, Any] = {
            "token": token,
            "type": file_type,
            "page_size": page_size,
        }
        if page_token:
            payload["page_token"] = page_token

        result = http_json_request(
            url=url,
            method="POST",
            payload=payload,
            access_token=access_token,
        )

        if result.get("code") != 0:
            raise RuntimeError(f"list drive permission members failed: {result}")

        data = result.get("data", {}) or {}
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []

        all_items.extend(items)

        has_more = bool(data.get("has_more", False))
        page_token = str(data.get("page_token") or data.get("next_page_token") or "").strip()

        if not has_more or not page_token:
            break

    return all_items


def list_drive_folder_items(
    access_token: str,
    folder_token: str,
    page_size: int = 200,
) -> List[Dict[str, Any]]:
    all_items: List[Dict[str, Any]] = []
    page_token = ""

    while True:
        qs = {
            "folder_token": folder_token,
            "page_size": str(page_size),
        }
        if page_token:
            qs["page_token"] = page_token

        url = "https://open.feishu.cn/open-apis/drive/v1/files?" + urllib.parse.urlencode(qs)

        result = http_json_request(
            url=url,
            method="GET",
            access_token=access_token,
        )

        if result.get("code") != 0:
            raise RuntimeError(f"list drive folder items failed: {result}")

        data = result.get("data", {}) or {}
        items = data.get("files", [])
        if not isinstance(items, list):
            items = []

        all_items.extend(items)

        has_more = bool(data.get("has_more", False))
        page_token = str(data.get("next_page_token", "")).strip()

        if not has_more or not page_token:
            break

    return all_items


def collect_descendant_tokens_under_folder(
    access_token: str,
    root_folder_token: str,
) -> List[str]:
    if not root_folder_token:
        return []

    result_tokens: Set[str] = set()
    visited_folders: Set[str] = set()
    queue: List[str] = [root_folder_token]

    while queue:
        folder_token = queue.pop(0)
        if not folder_token or folder_token in visited_folders:
            continue

        visited_folders.add(folder_token)
        result_tokens.add(folder_token)

        items = list_drive_folder_items(
            access_token=access_token,
            folder_token=folder_token,
        )

        for item in items:
            token = str(
                item.get("token")
                or item.get("file_token")
                or item.get("obj_token")
                or ""
            ).strip()
            item_type = str(
                item.get("type")
                or item.get("file_type")
                or ""
            ).strip().lower()

            if not token:
                continue

            result_tokens.add(token)

            if item_type == "folder" and token not in visited_folders:
                queue.append(token)

    return sorted(result_tokens)


def remove_all_direct_permissions_in_token(
    access_token: str,
    token: str,
) -> None:
    members = list_drive_permission_members(
        access_token=access_token,
        token=token,
    )

    for item in members:
        member_id = str(item.get("member_id") or item.get("id") or "").strip()
        member_type = str(item.get("member_type") or item.get("type") or "").strip()
        perm = str(item.get("perm") or item.get("permission") or "").strip().lower()

        if not member_id or not member_type:
            continue

        if perm in ["owner", "full_access_with_transfer_owner"]:
            print("skip owner-like member:", token, member_type, member_id, perm)
            continue

        safe_remove_drive_permission_member(
            access_token=access_token,
            token=token,
            member_id=member_id,
            member_type=member_type,
        )


def remove_drive_user_permission(access_token: str, token: str, member_open_id: str) -> None:
    try:
        result = delete_drive_permission_member(
            access_token=access_token,
            token=token,
            member_id=member_open_id,
            member_type=DRIVE_USER_MEMBER_TYPE,
        )
        print("delete permission success:", token, member_open_id)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as e:
        err = str(e)
        if "404" in err or "not found" in err.lower() or "不存在" in err:
            print("delete permission skipped, already gone:", token, member_open_id)
            return
        raise


def safe_remove_drive_user_permission(access_token: str, token: str, member_open_id: str) -> None:
    if not token or not member_open_id:
        return
    try:
        remove_drive_user_permission(access_token, token, member_open_id)
    except Exception as e:
        err = str(e)
        if "404" in err or "not found" in err.lower() or "already deleted" in err.lower():
            print("safe remove permission skipped:", token, member_open_id, err)
            return
        raise


def save_authed_project_state(
    tenant_access_token: str,
    record_id: str,
    tokens: Dict[str, Any],
    people: Dict[str, List[str]],
) -> None:
    update_bitable_record(
        tenant_access_token=tenant_access_token,
        record_id=record_id,
        fields={
            FIELD_AUTHED_MAIN_TOKEN: tokens["main_token"],
            FIELD_AUTHED_STUDENT_TOKENS: serialize_list(tokens["student_tokens"]),
            FIELD_AUTHED_EXTERNAL_TOKENS: serialize_list(tokens["external_tokens"]),
            FIELD_AUTHED_LEADER_OPEN_IDS: serialize_list(people["leader_open_ids"]),
            FIELD_AUTHED_STAFF_OPEN_IDS: serialize_list(people["staff_open_ids"]),
            FIELD_AUTHED_STUDENT_OPEN_IDS: serialize_list(people["student_open_ids"]),
            FIELD_AUTHED_EXTERNAL_OPEN_IDS: serialize_list(people["external_open_ids"]),
        },
    )


def apply_person_permissions(
    access_token: str,
    tokens: Dict[str, Any],
    people: Dict[str, List[str]],
    perms: Dict[str, str],
) -> None:
    main_token = tokens["main_token"]

    for open_id in people["leader_open_ids"]:
        if main_token:
            upsert_drive_user_permission(access_token, main_token, open_id, perms["leader_perm"])

    for open_id in people["staff_open_ids"]:
        if main_token:
            upsert_drive_user_permission(access_token, main_token, open_id, perms["staff_perm"])

    for token in tokens["student_tokens"]:
        for open_id in people["student_open_ids"]:
            upsert_drive_user_permission(access_token, token, open_id, perms["student_perm"])

    for token in tokens["external_tokens"]:
        for open_id in people["external_open_ids"]:
            upsert_drive_user_permission(access_token, token, open_id, perms["external_perm"])


def diff_set(old_items: List[str], new_items: List[str]) -> Tuple[Set[str], Set[str], Set[str]]:
    old_set = set(old_items)
    new_set = set(new_items)
    kept = old_set & new_set
    to_add = new_set - old_set
    to_remove = old_set - new_set
    return kept, to_add, to_remove


def sync_main_folder_permissions(
    access_token: str,
    old_main_token: str,
    new_main_token: str,
    old_leaders: List[str],
    new_leaders: List[str],
    old_staff: List[str],
    new_staff: List[str],
    leader_perm: str,
    staff_perm: str,
) -> None:
    # 如果总文件夹变了，先从旧 token 移除所有旧授权，再在新 token 上重建。
    if old_main_token and old_main_token != new_main_token:
        for open_id in old_leaders:
            safe_remove_drive_user_permission(access_token, old_main_token, open_id)
        for open_id in old_staff:
            safe_remove_drive_user_permission(access_token, old_main_token, open_id)

        old_leaders = []
        old_staff = []

    if not new_main_token:
        return

    kept, to_add, to_remove = diff_set(old_leaders, new_leaders)
    for open_id in to_remove:
        safe_remove_drive_user_permission(access_token, new_main_token, open_id)
    for open_id in kept | to_add:
        upsert_drive_user_permission(access_token, new_main_token, open_id, leader_perm)

    kept, to_add, to_remove = diff_set(old_staff, new_staff)
    for open_id in to_remove:
        safe_remove_drive_user_permission(access_token, new_main_token, open_id)
    for open_id in kept | to_add:
        upsert_drive_user_permission(access_token, new_main_token, open_id, staff_perm)


def sync_multi_token_permissions(
    access_token: str,
    old_tokens: List[str],
    new_tokens: List[str],
    old_open_ids: List[str],
    new_open_ids: List[str],
    perm: str,
) -> None:
    old_token_set = set(old_tokens)
    new_token_set = set(new_tokens)

    # 从已移除的 token 上，撤销旧人权限
    for token in sorted(old_token_set - new_token_set):
        for open_id in old_open_ids:
            safe_remove_drive_user_permission(access_token, token, open_id)

    # 对仍存在或新增的 token，按人员 diff 做精确同步
    for token in sorted(new_token_set):
        old_ids_for_token = old_open_ids if token in old_token_set else []
        kept, to_add, to_remove = diff_set(old_ids_for_token, new_open_ids)

        for open_id in to_remove:
            safe_remove_drive_user_permission(access_token, token, open_id)
        for open_id in kept | to_add:
            upsert_drive_user_permission(access_token, token, open_id, perm)


def clear_authed_state(tenant_access_token: str, record_id: str) -> None:
    update_bitable_record(
        tenant_access_token=tenant_access_token,
        record_id=record_id,
        fields={
            FIELD_AUTHED_MAIN_TOKEN: "",
            FIELD_AUTHED_STUDENT_TOKENS: "",
            FIELD_AUTHED_EXTERNAL_TOKENS: "",
            FIELD_AUTHED_LEADER_OPEN_IDS: "",
            FIELD_AUTHED_STAFF_OPEN_IDS: "",
            FIELD_AUTHED_STUDENT_OPEN_IDS: "",
            FIELD_AUTHED_EXTERNAL_OPEN_IDS: "",
        },
    )


# =========================
# Routes: enable / sync / decommission
# =========================
@app.post("/enable_project")
async def enable_project(
    request: Request,
    x_token: str = Header(default=None),
    x_source: str = Header(default=None),
):
    if WEBHOOK_SECRET and x_token != WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="invalid token")

    body = await parse_webhook_request(request, "/enable_project")
    record_id = str(body.get("record_id", "")).strip()
    if not record_id:
        return JSONResponse(status_code=400, content={"ok": False, "error": "record_id is empty"})

    try:
        tenant_access_token = get_feishu_tenant_access_token()
        record_result = get_bitable_record(tenant_access_token=tenant_access_token, record_id=record_id)
        fields = record_result["data"]["record"]["fields"]

        project_status = str(fields.get(FIELD_PROJECT_STATUS, "")).strip()
        if project_status != "启用":
            return JSONResponse(
                content={"ok": True, "message": "skip, project status is not 启用", "record_id": record_id}
            )

        update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields={
                FIELD_EXEC_STATUS: "处理中",
                FIELD_ERROR_INFO: "",
            },
        )

        current_tokens = get_current_project_tokens(fields)
        current_people = get_current_project_people(fields)
        current_perms = get_current_project_perms(fields)
        drive_access_token = get_admin_user_access_token()

        apply_person_permissions(
            access_token=drive_access_token,
            tokens=current_tokens,
            people=current_people,
            perms=current_perms,
        )

        save_authed_project_state(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            tokens=current_tokens,
            people=current_people,
        )

        update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields={
                FIELD_EXEC_STATUS: "成功",
                FIELD_ERROR_INFO: "",
            },
        )

        print("enable project success")
        return JSONResponse(content={"ok": True, "message": "project enabled", "record_id": record_id})

    except Exception as e:
        print("enable project failed:", repr(e))
        try:
            tenant_access_token = get_feishu_tenant_access_token()
            update_bitable_record(
                tenant_access_token=tenant_access_token,
                record_id=record_id,
                fields={
                    FIELD_EXEC_STATUS: "失败",
                    FIELD_ERROR_INFO: str(e),
                },
            )
        except Exception as e2:
            print("write enable error back failed:", repr(e2))

        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "error": "enable_project_failed",
                "detail": str(e),
                "record_id": record_id,
            },
        )


@app.post("/sync_project")
async def sync_project(
    request: Request,
    x_token: str = Header(default=None),
    x_source: str = Header(default=None),
):
    if WEBHOOK_SECRET and x_token != WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="invalid token")

    body = await parse_webhook_request(request, "/sync_project")
    record_id = str(body.get("record_id", "")).strip()
    if not record_id:
        return JSONResponse(status_code=400, content={"ok": False, "error": "record_id is empty"})

    try:
        tenant_access_token = get_feishu_tenant_access_token()
        record_result = get_bitable_record(tenant_access_token=tenant_access_token, record_id=record_id)
        fields = record_result["data"]["record"]["fields"]

        project_status = str(fields.get(FIELD_PROJECT_STATUS, "")).strip()
        if project_status != "启用":
            return JSONResponse(
                content={"ok": True, "message": "skip, project status is not 启用", "record_id": record_id}
            )

        update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields={
                FIELD_EXEC_STATUS: "处理中",
                FIELD_ERROR_INFO: "",
            },
        )

        old_tokens = get_authed_project_tokens(fields)
        old_people = get_authed_project_people(fields)
        new_tokens = get_current_project_tokens(fields)
        new_people = get_current_project_people(fields)
        new_perms = get_current_project_perms(fields)

        drive_access_token = get_admin_user_access_token()

        sync_main_folder_permissions(
            access_token=drive_access_token,
            old_main_token=old_tokens["main_token"],
            new_main_token=new_tokens["main_token"],
            old_leaders=old_people["leader_open_ids"],
            new_leaders=new_people["leader_open_ids"],
            old_staff=old_people["staff_open_ids"],
            new_staff=new_people["staff_open_ids"],
            leader_perm=new_perms["leader_perm"],
            staff_perm=new_perms["staff_perm"],
        )

        sync_multi_token_permissions(
            access_token=drive_access_token,
            old_tokens=old_tokens["student_tokens"],
            new_tokens=new_tokens["student_tokens"],
            old_open_ids=old_people["student_open_ids"],
            new_open_ids=new_people["student_open_ids"],
            perm=new_perms["student_perm"],
        )

        sync_multi_token_permissions(
            access_token=drive_access_token,
            old_tokens=old_tokens["external_tokens"],
            new_tokens=new_tokens["external_tokens"],
            old_open_ids=old_people["external_open_ids"],
            new_open_ids=new_people["external_open_ids"],
            perm=new_perms["external_perm"],
        )

        save_authed_project_state(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            tokens=new_tokens,
            people=new_people,
        )

        update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields={
                FIELD_EXEC_STATUS: "成功",
                FIELD_ERROR_INFO: "",
            },
        )

        print("sync project success")
        return JSONResponse(content={"ok": True, "message": "project synced", "record_id": record_id})

    except Exception as e:
        print("sync project failed:", repr(e))
        try:
            tenant_access_token = get_feishu_tenant_access_token()
            update_bitable_record(
                tenant_access_token=tenant_access_token,
                record_id=record_id,
                fields={
                    FIELD_EXEC_STATUS: "失败",
                    FIELD_ERROR_INFO: str(e),
                },
            )
        except Exception as e2:
            print("write sync project error back failed:", repr(e2))

        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "error": "sync_project_failed",
                "detail": str(e),
                "record_id": record_id,
            },
        )


@app.post("/decommission_project")
async def decommission_project(
    request: Request,
    x_token: str = Header(default=None),
    x_source: str = Header(default=None),
):
    if WEBHOOK_SECRET and x_token != WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="invalid token")

    body = await parse_webhook_request(request, "/decommission_project")
    record_id = str(body.get("record_id", "")).strip()
    if not record_id:
        return JSONResponse(status_code=400, content={"ok": False, "error": "record_id is empty"})

    try:
        tenant_access_token = get_feishu_tenant_access_token()
        record_result = get_bitable_record(tenant_access_token=tenant_access_token, record_id=record_id)
        fields = record_result["data"]["record"]["fields"]

        project_status = str(fields.get(FIELD_PROJECT_STATUS, "")).strip()
        if project_status != "停用":
            return JSONResponse(
                content={"ok": True, "message": "skip, project status is not 停用", "record_id": record_id}
            )

        exec_status = str(fields.get(FIELD_EXEC_STATUS, "")).strip()
        authed_tokens = get_authed_project_tokens(fields)
        authed_people = get_authed_project_people(fields)

        never_enabled = (
            exec_status not in ["成功", "已停用", "失败"]
            and not authed_tokens["main_token"]
            and not authed_tokens["student_tokens"]
            and not authed_tokens["external_tokens"]
            and not authed_people["leader_open_ids"]
            and not authed_people["staff_open_ids"]
            and not authed_people["student_open_ids"]
            and not authed_people["external_open_ids"]
        )

        if never_enabled:
            update_bitable_record(
                tenant_access_token=tenant_access_token,
                record_id=record_id,
                fields={
                    FIELD_EXEC_STATUS: "无需处理",
                    FIELD_ERROR_INFO: "项目尚未启用，无需停用",
                },
            )
            return JSONResponse(
                content={
                    "ok": True,
                    "message": "project never enabled, skip decommission",
                    "record_id": record_id,
                }
            )

        update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields={
                FIELD_EXEC_STATUS: "处理中",
                FIELD_ERROR_INFO: "",
            },
        )

        drive_access_token = get_admin_user_access_token()
        print("got admin user_access_token for decommission")

        current_tokens = get_current_project_tokens(fields)

        scope_tokens: Set[str] = set()

        main_token = current_tokens["main_token"] or authed_tokens["main_token"]
        if main_token:
            scope_tokens.update(
                collect_descendant_tokens_under_folder(
                    access_token=drive_access_token,
                    root_folder_token=main_token,
                )
            )

        scope_tokens.update(current_tokens["student_tokens"])
        scope_tokens.update(current_tokens["external_tokens"])
        scope_tokens.update(authed_tokens["student_tokens"])
        scope_tokens.update(authed_tokens["external_tokens"])

        print("decommission scope tokens:", sorted(scope_tokens))

        for token in sorted(scope_tokens):
            remove_all_direct_permissions_in_token(
                access_token=drive_access_token,
                token=token,
            )

        clear_authed_state(tenant_access_token, record_id)

        update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields={
                FIELD_EXEC_STATUS: "已停用",
                FIELD_ERROR_INFO: "",
            },
        )

        print("decommission success")
        return JSONResponse(
            content={
                "ok": True,
                "message": "project decommissioned",
                "record_id": record_id,
            }
        )

    except Exception as e:
        print("decommission failed:", repr(e))
        try:
            tenant_access_token = get_feishu_tenant_access_token()
            update_bitable_record(
                tenant_access_token=tenant_access_token,
                record_id=record_id,
                fields={
                    FIELD_EXEC_STATUS: "失败",
                    FIELD_ERROR_INFO: str(e),
                },
            )
        except Exception as e2:
            print("write decommission error back failed:", repr(e2))

        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "error": "decommission_failed",
                "detail": str(e),
                "record_id": record_id,
            },
        )


# =========================
# Old route compatibility
# =========================
@app.post("/init_project")
async def init_project_alias(
    request: Request,
    x_token: str = Header(default=None),
    x_source: str = Header(default=None),
):
    return await enable_project(request=request, x_token=x_token, x_source=x_source)


@app.post("/sync_members")
async def sync_members_alias(
    request: Request,
    x_token: str = Header(default=None),
    x_source: str = Header(default=None),
):
    return await sync_project(request=request, x_token=x_token, x_source=x_source)
