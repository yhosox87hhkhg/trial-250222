from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field, validator
import uvicorn
import secrets
import hashlib


app = FastAPI()
security = HTTPBasic()

users = {
    "TaroYamada": {
        "password": hashlib.sha256("PaSswd4TY".encode("utf-8")).hexdigest(),
        "nickname": "たろー",
        "comment": "僕は元気です"
    }
}

class SignupRequest(BaseModel):
    user_id: str = Field(..., min_length=6, max_length=20, pattern="^[a-zA-Z0-9]+$")
    password: str = Field(..., min_length=8, max_length=20, pattern=r'^[!-~]+$', repr=True)
    nickname: str | None = Field(None, max_length=30, pattern=r'^[^\x00-\x1F\x7F]*$')
    comment: str | None = Field(None, max_length=100, pattern=r'^[^\x00-\x1F\x7F]*$')

"""
class SignupRequest(BaseModel):
    user_id: str = Field(..., min_length=6, max_length=20, pattern="^[a-zA-Z0-9]+$")
    password: str = Field(..., min_length=8, max_length=20, pattern=r'^[!-~]+$')
"""

class UpdateRequest(BaseModel):
    nickname: str | None = Field(None, max_length=30, pattern=r'^[^\x00-\x1F\x7F]*$')
    comment: str | None = Field(None, max_length=100, pattern=r'^[^\x00-\x1F\x7F]*$')

class PasswordUpdateRequest(BaseModel):
    current_password: str = Field(..., min_length=8, max_length=20, pattern=r'^[!-~]+$')
    new_password: str = Field(..., min_length=8, max_length=20, pattern=r'^[!-~]+$')

# Debug

@app.get("/")
async def root():
    raise HTTPException(status_code=404, detail="Not Found")


# Basic authentication
def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    user_id = credentials.username
    # password = credentials.password
    password = hashlib.sha256(credentials.password.encode()).hexdigest()
    if user_id not in users or not secrets.compare_digest(users[user_id]["password"], password):
        raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Basic"})
    return user_id  # 認証成功時にユーザIDを返す

# get user information
@app.get("/users/{user_id}")
async def get_any_user(user_id: str, authenticated_user: str = Depends(authenticate_user)):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    # ユーザデータをコピーし、パスワードを削除
    user_data = users[user_id].copy()
    user_data.pop("password", None)
    return user_data

# add user
@app.post("/signup")
async def signup(request: SignupRequest):
    if request.user_id in users:
        raise HTTPException(status_code=400, detail="User ID already exists")
    # パスワードをSHA-256でハッシュ化
    hashed_password = hashlib.sha256(request.password.encode()).hexdigest()
    # 新しいユーザを追加
    users[request.user_id] = {
        "password": hashed_password,
        "nickname": request.nickname or "",
        "comment": request.comment or ""
    }
    # レスポンスから `nickname` と `comment` を省略する処理
    response_data = {
        "message": "Account successfully created",
        "user_id": request.user_id
    }
    if request.nickname is not None:
        response_data["nickname"] = request.nickname
    if request.comment is not None:
        response_data["comment"] = request.comment
    return response_data

# update user information
@app.patch("/users/{user_id}")
async def update_user(user_id: str, request: UpdateRequest, authenticated_user: str = Depends(authenticate_user)):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    # 自分の情報のみ更新可能
    if user_id != authenticated_user:
        raise HTTPException(status_code=403, detail="No Permission for Update")
    # 更新内容を反映
    if request.nickname is not None:
        users[user_id]["nickname"] = request.nickname
    if request.comment is not None:
        users[user_id]["comment"] = request.comment
    # レスポンスを作成（更新されたもののみ含める）
    response_data = {"message": "User updated successfully"}
    if request.nickname is not None:
        response_data["nickname"] = request.nickname
    if request.comment is not None:
        response_data["comment"] = request.comment
    return response_data

# update password
@app.patch("/users/{user_id}/password")
async def update_password(user_id: str, request: PasswordUpdateRequest, authenticated_user: str = Depends(authenticate_user)):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    # 自分のパスワードのみ更新可能
    if user_id != authenticated_user:
        raise HTTPException(status_code=403, detail="Permission denied")
    # 現在のパスワードをチェック
    hashed_current_password = hashlib.sha256(request.current_password.encode()).hexdigest()
    if not secrets.compare_digest(users[user_id]["password"], hashed_current_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    # 新しいパスワードをハッシュ化して保存
    users[user_id]["password"] = hashlib.sha256(request.new_password.encode()).hexdigest()
    return {"message": "Password updated successfully"}

# delete user account
@app.post("/close")
async def close_account(authenticated_user: str = Depends(authenticate_user)):
    # ユーザデータを削除
    del users[authenticated_user]
    return {"message": "Account deleted successfully"}
