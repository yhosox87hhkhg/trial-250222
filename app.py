from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel, Field
import base64
import re

app = FastAPI()

# メモリ上のユーザーデータ（アプリ再起動で消える）
users = {}

# Pydantic モデル（バリデーション付き）
class SignupRequest(BaseModel):
    user_id: str = Field(..., min_length=6, max_length=20, regex="^[a-zA-Z0-9]+$")
    password: str = Field(..., min_length=8, max_length=20, regex=r'^[!-~]+$')

class UpdateRequest(BaseModel):
    nickname: str | None = Field(None, max_length=30, regex=r'^[^\x00-\x1F\x7F]*$')
    comment: str | None = Field(None, max_length=100, regex=r'^[^\x00-\x1F\x7F]*$')

# ユーザ登録エンドポイント
@app.post("/signup")
def signup(request_data: SignupRequest):
    if request_data.user_id in users:
        raise HTTPException(status_code=400, detail={"message": "Account creation failed", "cause": "already same user_id is used"})

    users[request_data.user_id] = {
        "password": request_data.password,
        "nickname": request_data.user_id,
        "comment": ""
    }

    return {
        "message": "Account successfully created",
        "user": {
            "user_id": request_data.user_id,
            "nickname": request_data.user_id
        }
    }

# Basic 認証ヘルパー
def get_user_from_auth_header(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        return None

    try:
        decoded = base64.b64decode(auth_header.split(" ")[1]).decode("utf-8")
        user_id, password = decoded.split(":", 1)
    except:
        return None

    user = users.get(user_id)
    if not user or user["password"] != password:
        return None

    return user_id, user

# ユーザ情報取得エンドポイント
@app.get("/users/{user_id}")
def get_user(user_id: str, request: Request):
    auth_result = get_user_from_auth_header(request)
    if not auth_result:
        raise HTTPException(status_code=401, detail={"message": "Authentication Failed"})

    auth_user_id, user = auth_result

    if auth_user_id != user_id:
        raise HTTPException(status_code=404, detail={"message": "No User found"})

    return {
        "message": "User details by user_id",
        "user": {
            "user_id": auth_user_id,
            "nickname": user["nickname"],
            "comment": user["comment"]
        }
    }

# ユーザ情報更新エンドポイント
@app.patch("/users/{user_id}")
def update_user(user_id: str, request: Request, update_data: UpdateRequest):
    auth_result = get_user_from_auth_header(request)
    if not auth_result:
        raise HTTPException(status_code=401, detail={"message": "Authentication Failed"})

    auth_user_id, user = auth_result

    if auth_user_id != user_id:
        raise HTTPException(status_code=403, detail={"message": "No Permission for Update"})

    # nickname, comment の両方が None ならエラー
    if update_data.nickname is None and update_data.comment is None:
        raise HTTPException(status_code=400, detail={"message": "User updation failed", "cause": "required nickname or comment"})

    # user_id や password を変更しようとした場合はエラー
    if "user_id" in update_data.dict(exclude_unset=True) or "password" in update_data.dict(exclude_unset=True):
        raise HTTPException(status_code=400, detail={"message": "User updation failed", "cause": "not updatable user_id and password"})

    # 更新処理
    if update_data.nickname is not None:
        user["nickname"] = update_data.nickname if update_data.nickname else auth_user_id
    if update_data.comment is not None:
        user["comment"] = update_data.comment

    return {
        "message": "User successfully updated",
        "recipe": [
            {
                "nickname": user["nickname"],
                "comment": user["comment"]
            }
        ]
    }

# アカウント削除エンドポイント
@app.post("/close")
def close_account(request: Request):
    auth_result = get_user_from_auth_header(request)
    if not auth_result:
        raise HTTPException(status_code=401, detail={"message": "Authentication Failed"})

    auth_user_id, _ = auth_result
    del users[auth_user_id]

    return {"message": "Account and user successfully removed"}

