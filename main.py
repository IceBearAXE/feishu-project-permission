from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse
import os
import json
import re
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Set

app = FastAPI()

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
FEISHU_APP_ID = os.getenv("FEISHU_APP_ID", "")
FEISHU_APP_SECRET = os.getenv("FEISHU_APP_SECRET", "")
BITABLE_APP_TOKEN = os.getenv("BITABLE_APP_TOKEN", "")
BITABLE_TABLE_ID = os.getenv("BITABLE_TABLE_ID", "")


@app.get("/")
async def root():
    return {"ok": True, "message": "service is running"}


def parse_loose_feishu_body(raw_text: str) -> Dict[str, str]:
    """
    兼容飞书自动化发来的这种“伪 JSON”：
    {
      "record_id": recxxxx,
      "project_code": AUTO-TEST-013,
      "project_name": AUTO-TEST-013,
      "folder_token": TOKEN-AUTO-013
    }
    """
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

    payload = {
        "fields": fields
    }

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


def extract_open_ids(field_value: Any) -> List[str]:
    """
    人员字段通常是:
    [
      {
        "id": "ou_xxx",
        "name": "张三",
        ...
      }
    ]
    """
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
    project_code = str(body.get("project_code", "")).strip()
    project_name = str(body.get("project_name", "")).strip()
    folder_token = str(body.get("folder_token", "")).strip()

    if not record_id:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "record_id is empty"}
        )

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

    created_groups: List[Dict[str, Any]] = []

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
        "初始化状态": "成功"
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

    return JSONResponse(
        content={
            "ok": True,
            "message": "groups created and record updated",
            "record_id": record_id,
            "project_code": project_code,
            "project_name": project_name,
            "folder_token": folder_token,
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
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "record_id is empty"}
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
            content={
                "ok": False,
                "error": "get_bitable_record_failed",
                "detail": str(e),
                "record_id": record_id
            }
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
                "错误信息": ""
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
                    "错误信息": str(e)
                }
            )
        except Exception as e2:
            print("write sync error back failed:", repr(e2))

        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "error": "sync_members_failed",
                "detail": str(e),
                "record_id": record_id
            }
        )

    return JSONResponse(
        content={
            "ok": True,
            "message": "members synced",
            "record_id": record_id
        }
    )