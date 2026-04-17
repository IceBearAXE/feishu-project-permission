import json
import os
import re
import time
import urllib.parse
from typing import Any, Dict, List, Set

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
ADMIN_REFRESH_TOKEN_CACHE = ""  # 不要预置成环境变量，优先从配置表读取

# =========================
# Field names
# =========================
FIELD_PROJECT_CODE = "项目编号"
FIELD_PROJECT_NAME = "项目名称"
FIELD_PROJECT_STATUS = "项目状态"

FIELD_MAIN_FOLDER_LINK = "总文件夹链接"
FIELD_STUDENT_LINKS = "学生权限链接列表"
FIELD_EXTERNAL_LINKS = "总体单位权限链接列表"

FIELD_LEADER_MEMBERS = "项目负责人"
FIELD_STAFF_MEMBERS = "员工"
FIELD_STUDENT_MEMBERS = "学生"
FIELD_EXTERNAL_MEMBERS = "总体单位"

FIELD_LEADER_GROUP_ID = "负责人组ID"
FIELD_STAFF_GROUP_ID = "员工组ID"
FIELD_STUDENT_GROUP_ID = "学生组ID"
FIELD_EXTERNAL_GROUP_ID = "总体单位ID"

FIELD_INIT_STATUS = "初始化状态"
FIELD_SYNC_STATUS = "同步状态"
FIELD_AUTH_STATUS = "授权状态"
FIELD_DECOMMISSION_STATUS = "停用状态"

FIELD_SYNC_ERROR = "同步错误信息"
FIELD_AUTH_ERROR = "授权错误信息"
FIELD_DECOMMISSION_ERROR = "停用错误信息"

FIELD_AUTHED_MAIN_TOKEN = "已授权总文件夹token"
FIELD_AUTHED_STUDENT_TOKENS = "已授权学生token列表"
FIELD_AUTHED_EXTERNAL_TOKENS = "已授权总体单位token列表"

# =========================
# Permission constants
# =========================
DRIVE_GROUP_MEMBER_TYPE = "groupid"
DRIVE_MANAGER_PERMISSION = "full_access"
DRIVE_EDIT_PERMISSION = "edit"
DRIVE_READ_PERMISSION = "view"

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
    """
    兼容飞书自动化有时发来的“看起来像 JSON 但值没加引号”的 body。
    当前我们最主要只需要 record_id。
    """
    text = (raw_text or "").strip()
    if not text:
        return {}

    # 先尝试把简单 bareword 值补上引号
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

    # 最后兜底：只抽 record_id
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
    # 当前业务场景里你填的都是文件夹链接，所以这里统一按 folder 处理。
    # 如果后面你真的要支持 doc/wiki/sheet，再扩展这层。
    if not token:
        return ""
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


def parse_persisted_token_list(value: Any) -> List[str]:
    text = str(value or "").strip()
    if not text:
        return []
    return sorted(set([x.strip() for x in text.splitlines() if x.strip()]))


def serialize_token_list(tokens: List[str]) -> str:
    return "\n".join(sorted(set([str(x).strip() for x in tokens if str(x).strip()])))


def get_project_code(fields: Dict[str, Any]) -> str:
    project_code = str(fields.get(FIELD_PROJECT_CODE, "")).strip()
    if project_code:
        return project_code
    return str(fields.get(FIELD_PROJECT_NAME, "")).strip()


def build_project_group_names(fields: Dict[str, Any]) -> Dict[str, str]:
    base = get_project_code(fields)
    if not base:
        raise RuntimeError("项目编号和项目名称不能同时为空")

    return {
        "leader": f"{base}-项目负责人",
        "staff": f"{base}-员工",
        "student": f"{base}-学生",
        "external": f"{base}-总体单位",
    }


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

def get_current_user_info(user_access_token: str) -> Dict[str, Any]:
    url = "https://open.feishu.cn/open-apis/authen/v1/user_info"
    result = http_json_request(
        url=url,
        method="GET",
        access_token=user_access_token
    )
    if result.get("code") != 0:
        raise RuntimeError(f"get current user info failed: {result}")
    return result.get("data", {})


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
# Group helpers
# =========================
def create_user_group(tenant_access_token: str, group_name: str) -> str:
    url = "https://open.feishu.cn/open-apis/contact/v3/group"
    payload = {
        "name": group_name,
    }

    result = http_json_request(
        url=url,
        method="POST",
        payload=payload,
        access_token=tenant_access_token,
    )

    if result.get("code") != 0:
        raise RuntimeError(f"create user group failed: {result}")

    data = result.get("data", {})
    group_obj = data.get("group", {}) if isinstance(data.get("group"), dict) else {}

    group_id = (
        str(data.get("group_id", "")).strip()
        or str(data.get("id", "")).strip()
        or str(group_obj.get("group_id", "")).strip()
        or str(group_obj.get("id", "")).strip()
    )

    if not group_id:
        raise RuntimeError(f"group_id missing in create user group response: {result}")

    return group_id


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
            access_token=tenant_access_token,
        )

        print(f"[list_group_member_open_ids] raw result for group {group_id}:")
        print(json.dumps(result, ensure_ascii=False, indent=2))

        if result.get("code") != 0:
            raise RuntimeError(f"list group members failed: {result}")

        data = result.get("data", {})
        items = data.get("memberlist", [])
        if not isinstance(items, list):
            items = []

        for item in items:
            if not isinstance(item, dict):
                continue
            member_id = str(item.get("member_id", "")).strip()
            if member_id:
                member_ids.append(member_id)

        if not data.get("has_more"):
            break

        page_token = str(data.get("page_token", "")).strip()
        if not page_token:
            break

    result_ids: List[str] = []
    seen = set()
    for x in member_ids:
        if x not in seen:
            seen.add(x)
            result_ids.append(x)

    print(f"[list_group_member_open_ids] parsed member ids for group {group_id}: {result_ids}")
    return result_ids


def add_group_member(tenant_access_token: str, group_id: str, open_id: str) -> Dict[str, Any]:
    url = f"https://open.feishu.cn/open-apis/contact/v3/group/{group_id}/member/add"
    payload = {
        "member_type": "user",
        "member_id_type": "open_id",
        "member_id": open_id,
    }

    try:
        result = http_json_request(
            url=url,
            method="POST",
            payload=payload,
            access_token=tenant_access_token,
        )
    except Exception as e:
        err = str(e)
        if "42005" in err or "member exist in group" in err:
            print("add group member skipped, member already exists:", open_id, "in", group_id)
            return {"code": 42005, "msg": "member exist in group", "skipped": True}
        raise

    if result.get("code") != 0:
        if result.get("code") == 42005:
            print("add group member skipped, member already exists:", open_id, "in", group_id)
            result["skipped"] = True
            return result
        raise RuntimeError(f"add group member failed: {result}")

    result["skipped"] = False
    return result


def remove_group_member(tenant_access_token: str, group_id: str, open_id: str) -> Dict[str, Any]:
    url = f"https://open.feishu.cn/open-apis/contact/v3/group/{group_id}/member/remove"
    payload = {
        "member_type": "user",
        "member_id_type": "open_id",
        "member_id": open_id,
    }

    result = http_json_request(
        url=url,
        method="POST",
        payload=payload,
        access_token=tenant_access_token,
    )

    if result.get("code") != 0:
        raise RuntimeError(f"remove group member failed: {result}")

    return result


def delete_user_group(tenant_access_token: str, group_id: str) -> Dict[str, Any]:
    url = f"https://open.feishu.cn/open-apis/contact/v3/group/{group_id}"

    try:
        result = http_json_request(
            url=url,
            method="DELETE",
            access_token=tenant_access_token,
        )
    except Exception as e:
        err = str(e)
        if (
            "404" in err
            or "not found" in err.lower()
            or "不存在" in err
            or "42002" in err
            or "invalid group_id" in err.lower()
        ):
            print("delete user group skipped, invalid or already gone:", group_id)
            return {"code": 0, "msg": "already deleted or invalid"}
        raise

    if result.get("code") != 0:
        if result.get("code") == 42002:
            print("delete user group skipped, invalid group_id:", group_id)
            return {"code": 0, "msg": "already deleted or invalid"}
        raise RuntimeError(f"delete user group failed: {result}")

    return result


def clear_user_group_members(tenant_access_token: str, group_id: str) -> None:
    try:
        current_open_ids = list_group_member_open_ids(tenant_access_token, group_id)
    except Exception as e:
        err = str(e)
        if "42002" in err or "invalid group_id" in err.lower():
            print("clear_user_group_members skipped, invalid group_id:", group_id)
            return
        raise

    print(f"[clear_user_group_members] group {group_id} current members =", current_open_ids)

    for open_id in current_open_ids:
        try:
            remove_group_member(tenant_access_token, group_id, open_id)
            print(f"[clear_user_group_members] removed {open_id} from {group_id}")
        except Exception as e:
            err = str(e)
            if "42002" in err or "invalid group_id" in err.lower():
                print("remove member skipped, invalid group_id:", group_id)
                return
            raise


def is_valid_group_id(tenant_access_token: str, group_id: str) -> bool:
    if not group_id:
        return False
    try:
        list_group_member_open_ids(tenant_access_token, group_id)
        return True
    except Exception as e:
        err = str(e)
        if "42002" in err or "invalid group_id" in err.lower():
            return False
        raise


def ensure_user_group(tenant_access_token: str, group_id: str, group_name: str) -> str:
    if group_id and is_valid_group_id(tenant_access_token, group_id):
        return group_id

    new_group_id = create_user_group(tenant_access_token, group_name)
    print("created new group:", group_name, new_group_id)
    return new_group_id


# =========================
# Permission helpers
# =========================
def upsert_drive_group_permission(
    access_token: str,
    token: str,
    member_group_id: str,
    perm: str,
) -> None:
    file_type = get_drive_type_from_token(token)
    if not file_type:
        raise RuntimeError(f"cannot infer file type from token: {token}")

    url = (
        f"https://open.feishu.cn/open-apis/drive/v1/permissions/{token}/members"
        f"?type={urllib.parse.quote(file_type)}"
    )

    payload = {
        "member_type": DRIVE_GROUP_MEMBER_TYPE,
        "member_id": member_group_id,
        "perm": perm,
    }

    try:
        result = http_json_request(
            url=url,
            method="POST",
            payload=payload,
            access_token=access_token,
        )
    except Exception as e:
        err = str(e)
        if "exist" in err.lower() or "already" in err.lower():
            print("upsert permission skipped, already exists:", token, member_group_id, perm)
            return
        raise

    if result.get("code") != 0:
        msg = str(result.get("msg", "")).lower()
        if "exist" in msg or "already" in msg:
            print("upsert permission skipped, already exists:", token, member_group_id, perm)
            return
        raise RuntimeError(f"upsert drive group permission failed: {result}")

    print("create permission success:", token, member_group_id, perm)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def upsert_drive_group_permission_with_retry(
    access_token: str,
    token: str,
    member_group_id: str,
    perm: str,
    max_retries: int = 5,
    sleep_seconds: int = 2
) -> None:
    last_error = None

    for i in range(max_retries):
        try:
            upsert_drive_group_permission(
                access_token=access_token,
                token=token,
                member_group_id=member_group_id,
                perm=perm
            )
            return
        except Exception as e:
            err = str(e)
            last_error = e

            # 只对这种“刚建组后授权失败”的疑似同步延迟做重试
            if "1063002" in err or "Permission denied" in err:
                print(
                    f"[AUTH RETRY] attempt {i + 1}/{max_retries} failed:",
                    token,
                    member_group_id,
                    perm,
                    err
                )
                if i < max_retries - 1:
                    time.sleep(sleep_seconds)
                    continue

            raise

    if last_error:
        raise last_error


def delete_drive_permission_member(access_token: str, token: str, member_id: str) -> Dict[str, Any]:
    file_type = get_drive_type_from_token(token)
    if not file_type:
        raise RuntimeError(f"cannot infer file type from token: {token}")

    url = (
        f"https://open.feishu.cn/open-apis/drive/v1/permissions/{token}/members/"
        f"{urllib.parse.quote(member_id)}"
        f"?type={urllib.parse.quote(file_type)}"
        f"&member_type={urllib.parse.quote(DRIVE_GROUP_MEMBER_TYPE)}"
    )

    try:
        result = http_json_request(
            url=url,
            method="DELETE",
            access_token=access_token,
        )
    except Exception as e:
        err = str(e)
        if "404" in err or "not found" in err.lower() or "不存在" in err:
            print("delete permission skipped, already gone:", token, member_id)
            return {"code": 0, "msg": "already deleted"}
        raise

    if result.get("code") != 0:
        raise RuntimeError(f"delete drive permission member failed: {result}")

    return result


def remove_drive_group_permission(access_token: str, token: str, member_group_id: str) -> None:
    result = delete_drive_permission_member(
        access_token=access_token,
        token=token,
        member_id=member_group_id,
    )
    print("delete permission success:", token, member_group_id)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def safe_remove_drive_group_permission(access_token: str, token: str, member_group_id: str) -> None:
    if not token or not member_group_id:
        return
    try:
        remove_drive_group_permission(access_token, token, member_group_id)
    except Exception as e:
        err = str(e)
        if (
            "404" in err
            or "42002" in err
            or "not found" in err.lower()
            or "invalid group_id" in err.lower()
            or "already deleted" in err.lower()
        ):
            print("safe remove permission skipped:", token, member_group_id, err)
            return
        raise


def apply_project_permissions(
    access_token: str,
    main_token: str,
    student_tokens: List[str],
    external_tokens: List[str],
    leader_group_id: str,
    staff_group_id: str,
    student_group_id: str,
    external_group_id: str
) -> None:
    if main_token and leader_group_id:
        print("[AUTH] start main folder leader", main_token, leader_group_id, DRIVE_MANAGER_PERMISSION)
        upsert_drive_group_permission_with_retry(
            access_token=access_token,
            token=main_token,
            member_group_id=leader_group_id,
            perm=DRIVE_MANAGER_PERMISSION
        )
        print("[AUTH] success main folder leader", main_token, leader_group_id, DRIVE_MANAGER_PERMISSION)

    if main_token and staff_group_id:
        print("[AUTH] start main folder staff", main_token, staff_group_id, DRIVE_EDIT_PERMISSION)
        upsert_drive_group_permission_with_retry(
            access_token=access_token,
            token=main_token,
            member_group_id=staff_group_id,
            perm=DRIVE_EDIT_PERMISSION
        )
        print("[AUTH] success main folder staff", main_token, staff_group_id, DRIVE_EDIT_PERMISSION)

    for token in student_tokens:
        if student_group_id:
            print("[AUTH] start student folder", token, student_group_id, DRIVE_EDIT_PERMISSION)
            upsert_drive_group_permission_with_retry(
                access_token=access_token,
                token=token,
                member_group_id=student_group_id,
                perm=DRIVE_EDIT_PERMISSION
            )
            print("[AUTH] success student folder", token, student_group_id, DRIVE_EDIT_PERMISSION)

    for token in external_tokens:
        if external_group_id:
            print("[AUTH] start external folder", token, external_group_id, DRIVE_READ_PERMISSION)
            upsert_drive_group_permission_with_retry(
                access_token=access_token,
                token=token,
                member_group_id=external_group_id,
                perm=DRIVE_READ_PERMISSION
            )
            print("[AUTH] success external folder", token, external_group_id, DRIVE_READ_PERMISSION)


# =========================
# Project token state helpers
# =========================
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


def get_authed_project_tokens(fields: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "main_token": str(fields.get(FIELD_AUTHED_MAIN_TOKEN, "")).strip(),
        "student_tokens": parse_persisted_token_list(fields.get(FIELD_AUTHED_STUDENT_TOKENS, "")),
        "external_tokens": parse_persisted_token_list(fields.get(FIELD_AUTHED_EXTERNAL_TOKENS, "")),
    }


def save_authed_project_tokens(
    tenant_access_token: str,
    record_id: str,
    main_token: str,
    student_tokens: List[str],
    external_tokens: List[str],
) -> None:
    update_bitable_record(
        tenant_access_token=tenant_access_token,
        record_id=record_id,
        fields={
            FIELD_AUTHED_MAIN_TOKEN: main_token,
            FIELD_AUTHED_STUDENT_TOKENS: serialize_token_list(student_tokens),
            FIELD_AUTHED_EXTERNAL_TOKENS: serialize_token_list(external_tokens),
        },
    )


# =========================
# Group sync helpers
# =========================
def sync_one_group(
    tenant_access_token: str,
    group_id: str,
    target_open_ids: List[str],
    role_name: str,
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
        add_result = add_group_member(tenant_access_token, group_id, open_id)
        if add_result.get("skipped"):
            print(f"[{role_name}] skipped add:", open_id)
        else:
            print(f"[{role_name}] added:", open_id)

    for open_id in to_remove:
        remove_group_member(tenant_access_token, group_id, open_id)
        print(f"[{role_name}] removed:", open_id)


def sync_all_project_groups(
    tenant_access_token: str,
    fields: Dict[str, Any],
    leader_group_id: str,
    staff_group_id: str,
    student_group_id: str,
    external_group_id: str,
) -> None:
    leader_open_ids = extract_people_open_ids(fields.get(FIELD_LEADER_MEMBERS, []))
    staff_open_ids = extract_people_open_ids(fields.get(FIELD_STAFF_MEMBERS, []))
    student_open_ids = extract_people_open_ids(fields.get(FIELD_STUDENT_MEMBERS, []))
    external_open_ids = extract_people_open_ids(fields.get(FIELD_EXTERNAL_MEMBERS, []))

    if leader_group_id:
        sync_one_group(tenant_access_token, leader_group_id, leader_open_ids, "项目负责人")
    if staff_group_id:
        sync_one_group(tenant_access_token, staff_group_id, staff_open_ids, "员工")
    if student_group_id:
        sync_one_group(tenant_access_token, student_group_id, student_open_ids, "学生")
    if external_group_id:
        sync_one_group(tenant_access_token, external_group_id, external_open_ids, "总体单位")


# =========================
# Request parser
# =========================
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
# New routes
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
                FIELD_INIT_STATUS: "处理中",
                FIELD_SYNC_STATUS: "处理中",
                FIELD_AUTH_STATUS: "处理中",
                FIELD_SYNC_ERROR: "",
                FIELD_AUTH_ERROR: "",
            },
        )

        group_names = build_project_group_names(fields)

        leader_group_id = ensure_user_group(
            tenant_access_token,
            str(fields.get(FIELD_LEADER_GROUP_ID, "")).strip(),
            group_names["leader"],
        )
        staff_group_id = ensure_user_group(
            tenant_access_token,
            str(fields.get(FIELD_STAFF_GROUP_ID, "")).strip(),
            group_names["staff"],
        )
        student_group_id = ensure_user_group(
            tenant_access_token,
            str(fields.get(FIELD_STUDENT_GROUP_ID, "")).strip(),
            group_names["student"],
        )
        external_group_id = ensure_user_group(
            tenant_access_token,
            str(fields.get(FIELD_EXTERNAL_GROUP_ID, "")).strip(),
            group_names["external"],
        )

        # 先把组ID落表，避免后续半路失败后无法清理
        update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields={
                FIELD_LEADER_GROUP_ID: leader_group_id,
                FIELD_STAFF_GROUP_ID: staff_group_id,
                FIELD_STUDENT_GROUP_ID: student_group_id,
                FIELD_EXTERNAL_GROUP_ID: external_group_id,
            },
        )

        sync_all_project_groups(
            tenant_access_token=tenant_access_token,
            fields=fields,
            leader_group_id=leader_group_id,
            staff_group_id=staff_group_id,
            student_group_id=student_group_id,
            external_group_id=external_group_id,
        )

        current_tokens = get_current_project_tokens(fields)
        drive_access_token = get_admin_user_access_token()
        current_user = get_current_user_info(drive_access_token)
        print("current admin user info =", json.dumps(current_user, ensure_ascii=False))

        apply_project_permissions(
            access_token=drive_access_token,
            main_token=current_tokens["main_token"],
            student_tokens=current_tokens["student_tokens"],
            external_tokens=current_tokens["external_tokens"],
            leader_group_id=leader_group_id,
            staff_group_id=staff_group_id,
            student_group_id=student_group_id,
            external_group_id=external_group_id,
        )

        save_authed_project_tokens(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            main_token=current_tokens["main_token"],
            student_tokens=current_tokens["student_tokens"],
            external_tokens=current_tokens["external_tokens"],
        )

        update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields={
                FIELD_LEADER_GROUP_ID: leader_group_id,
                FIELD_STAFF_GROUP_ID: staff_group_id,
                FIELD_STUDENT_GROUP_ID: student_group_id,
                FIELD_EXTERNAL_GROUP_ID: external_group_id,
                FIELD_INIT_STATUS: "成功",
                FIELD_SYNC_STATUS: "成功",
                FIELD_AUTH_STATUS: "成功",
                FIELD_DECOMMISSION_STATUS: "",
                FIELD_DECOMMISSION_ERROR: "",
                FIELD_SYNC_ERROR: "",
                FIELD_AUTH_ERROR: "",
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
                    FIELD_INIT_STATUS: "失败",
                    FIELD_SYNC_STATUS: "失败",
                    FIELD_AUTH_STATUS: "失败",
                    FIELD_AUTH_ERROR: str(e),
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
                FIELD_SYNC_STATUS: "处理中",
                FIELD_AUTH_STATUS: "处理中",
                FIELD_SYNC_ERROR: "",
                FIELD_AUTH_ERROR: "",
            },
        )

        group_names = build_project_group_names(fields)

        leader_group_id = ensure_user_group(
            tenant_access_token,
            str(fields.get(FIELD_LEADER_GROUP_ID, "")).strip(),
            group_names["leader"],
        )
        staff_group_id = ensure_user_group(
            tenant_access_token,
            str(fields.get(FIELD_STAFF_GROUP_ID, "")).strip(),
            group_names["staff"],
        )
        student_group_id = ensure_user_group(
            tenant_access_token,
            str(fields.get(FIELD_STUDENT_GROUP_ID, "")).strip(),
            group_names["student"],
        )
        external_group_id = ensure_user_group(
            tenant_access_token,
            str(fields.get(FIELD_EXTERNAL_GROUP_ID, "")).strip(),
            group_names["external"],
        )

        update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields={
                FIELD_LEADER_GROUP_ID: leader_group_id,
                FIELD_STAFF_GROUP_ID: staff_group_id,
                FIELD_STUDENT_GROUP_ID: student_group_id,
                FIELD_EXTERNAL_GROUP_ID: external_group_id,
            },
        )

        sync_all_project_groups(
            tenant_access_token=tenant_access_token,
            fields=fields,
            leader_group_id=leader_group_id,
            staff_group_id=staff_group_id,
            student_group_id=student_group_id,
            external_group_id=external_group_id,
        )

        old_tokens = get_authed_project_tokens(fields)
        new_tokens = get_current_project_tokens(fields)

        drive_access_token = get_admin_user_access_token()

        old_main_token = old_tokens["main_token"]
        new_main_token = new_tokens["main_token"]

        if old_main_token and old_main_token != new_main_token:
            safe_remove_drive_group_permission(drive_access_token, old_main_token, leader_group_id)
            safe_remove_drive_group_permission(drive_access_token, old_main_token, staff_group_id)

        if new_main_token:
            upsert_drive_group_permission(drive_access_token, new_main_token, leader_group_id, DRIVE_MANAGER_PERMISSION)
            upsert_drive_group_permission(drive_access_token, new_main_token, staff_group_id, DRIVE_EDIT_PERMISSION)

        old_student_set = set(old_tokens["student_tokens"])
        new_student_set = set(new_tokens["student_tokens"])

        for token in sorted(old_student_set - new_student_set):
            safe_remove_drive_group_permission(drive_access_token, token, student_group_id)

        for token in sorted(new_student_set):
            upsert_drive_group_permission(drive_access_token, token, student_group_id, DRIVE_EDIT_PERMISSION)

        old_external_set = set(old_tokens["external_tokens"])
        new_external_set = set(new_tokens["external_tokens"])

        for token in sorted(old_external_set - new_external_set):
            safe_remove_drive_group_permission(drive_access_token, token, external_group_id)

        for token in sorted(new_external_set):
            upsert_drive_group_permission(drive_access_token, token, external_group_id, DRIVE_READ_PERMISSION)

        save_authed_project_tokens(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            main_token=new_tokens["main_token"],
            student_tokens=new_tokens["student_tokens"],
            external_tokens=new_tokens["external_tokens"],
        )

        update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields={
                FIELD_LEADER_GROUP_ID: leader_group_id,
                FIELD_STAFF_GROUP_ID: staff_group_id,
                FIELD_STUDENT_GROUP_ID: student_group_id,
                FIELD_EXTERNAL_GROUP_ID: external_group_id,
                FIELD_SYNC_STATUS: "成功",
                FIELD_AUTH_STATUS: "成功",
                FIELD_SYNC_ERROR: "",
                FIELD_AUTH_ERROR: "",
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
                    FIELD_SYNC_STATUS: "失败",
                    FIELD_AUTH_STATUS: "失败",
                    FIELD_AUTH_ERROR: str(e),
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

        leader_group_id = str(fields.get(FIELD_LEADER_GROUP_ID, "")).strip()
        staff_group_id = str(fields.get(FIELD_STAFF_GROUP_ID, "")).strip()
        student_group_id = str(fields.get(FIELD_STUDENT_GROUP_ID, "")).strip()
        external_group_id = str(fields.get(FIELD_EXTERNAL_GROUP_ID, "")).strip()

        init_status = str(fields.get(FIELD_INIT_STATUS, "")).strip()
        never_enabled = (
            init_status != "成功"
            and not leader_group_id
            and not staff_group_id
            and not student_group_id
            and not external_group_id
        )

        if never_enabled:
            update_bitable_record(
                tenant_access_token=tenant_access_token,
                record_id=record_id,
                fields={
                    FIELD_DECOMMISSION_STATUS: "无需处理",
                    FIELD_DECOMMISSION_ERROR: "项目尚未启用，无需停用",
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
                FIELD_DECOMMISSION_STATUS: "处理中",
                FIELD_DECOMMISSION_ERROR: "",
            },
        )

        authed_tokens = get_authed_project_tokens(fields)
        current_tokens = get_current_project_tokens(fields)

        main_token = authed_tokens["main_token"] or current_tokens["main_token"]
        student_tokens = authed_tokens["student_tokens"] or current_tokens["student_tokens"]
        external_tokens = authed_tokens["external_tokens"] or current_tokens["external_tokens"]

        drive_access_token = get_admin_user_access_token()
        print("got admin user_access_token for decommission")

        if main_token and leader_group_id:
            safe_remove_drive_group_permission(drive_access_token, main_token, leader_group_id)
        if main_token and staff_group_id:
            safe_remove_drive_group_permission(drive_access_token, main_token, staff_group_id)

        for token in student_tokens:
            if student_group_id:
                safe_remove_drive_group_permission(drive_access_token, token, student_group_id)

        for token in external_tokens:
            if external_group_id:
                safe_remove_drive_group_permission(drive_access_token, token, external_group_id)

        for gid in [leader_group_id, staff_group_id, student_group_id, external_group_id]:
            if not gid:
                continue

            try:
                clear_user_group_members(tenant_access_token, gid)
            except Exception as e:
                print("clear group members failed but continue:", gid, repr(e))

            try:
                delete_user_group(tenant_access_token, gid)
            except Exception as e:
                print("delete user group failed but continue:", gid, repr(e))

        update_bitable_record(
            tenant_access_token=tenant_access_token,
            record_id=record_id,
            fields={
                FIELD_LEADER_GROUP_ID: "",
                FIELD_STAFF_GROUP_ID: "",
                FIELD_STUDENT_GROUP_ID: "",
                FIELD_EXTERNAL_GROUP_ID: "",
                FIELD_AUTHED_MAIN_TOKEN: "",
                FIELD_AUTHED_STUDENT_TOKENS: "",
                FIELD_AUTHED_EXTERNAL_TOKENS: "",
                FIELD_DECOMMISSION_STATUS: "成功",
                FIELD_DECOMMISSION_ERROR: "",
                FIELD_AUTH_STATUS: "已停用",
                FIELD_SYNC_STATUS: "已停用",
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
                    FIELD_DECOMMISSION_STATUS: "失败",
                    FIELD_DECOMMISSION_ERROR: str(e),
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