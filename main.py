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
    x_token: str | None = Header(default=None)
):
    # 校验你和飞书自动化约定的密钥
    if WEBHOOK_SECRET and x_token != WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="invalid token")

    body = await request.json()

    # 先只打印日志，确认飞书真的打进来了
    print("====== received /init_project ======")
    print(json.dumps(body, ensure_ascii=False, indent=2))

    # 先返回成功，后面再加“创建用户组、授权文件夹、回写表格”
    return JSONResponse({
        "ok": True,
        "message": "request received",
        "received": body
    })