from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, ValidationError
import uvicorn
import hashlib
import secrets
import re
from typing import Dict, List, Optional, Union

class User(BaseModel):
    user_id: str
    password: str
    nickname: str = ""
    comment: str = ""

class UserResponse(BaseModel):
    user_id: str
    nickname: str
    comment: str

class UserDetailResponse(BaseModel):
    message: str = "User details by user_id"
    user: UserResponse

class SignupRequest(BaseModel):
    user_id: str = Field(..., min_length=6, max_length=20)
    password: str = Field(..., min_length=8, max_length=20)
    nickname: Optional[str] = Field(None, max_length=30)
    comment: Optional[str] = Field(None, max_length=100)
    # ✅ `user_id` のバリデーション（英数字のみ）
    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9]+$", v):
            raise HTTPException(status_code=400, detail={"message": "Account creation failed", "cause": "user_id must contain only alphanumeric characters"})
        return v
    # ✅ `password` のバリデーション（英大小・数字・記号を含む）
    @field_validator("password", mode="before")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).+$", v):
            raise HTTPException(status_code=400, detail={"message": "Account creation failed", "cause": "password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"})
        return v
    # ✅ `nickname`・`comment` のバリデーション（制御文字禁止）
    @field_validator("nickname", "comment")
    @classmethod
    def validate_text(cls, v: str) -> str:
        if v and re.search(r"[\x00-\x1F\x7F]", v):
            raise HTTPException(status_code=400, detail={"message": "Account creation failed", "cause": "Invalid characters in text"})
        return v

class UserUpdateRequest(BaseModel):
    user_id: Optional[str] = None
    password: Optional[str] = None
    nickname: Optional[str] = Field(None, max_length=30)
    comment: Optional[str] = Field(None, max_length=100)
    # ✅ `nickname`・`comment` のバリデーション（制御文字禁止）
    @field_validator("nickname", "comment")
    @classmethod
    def validate_text(cls, v: Optional[str]) -> Optional[str]:
        if v and re.search(r"[\x00-\x1F\x7F]", v):
            raise HTTPException(status_code=400, detail={"message": "User update failed", "cause": "Invalid characters in text"})
        return v



users: Dict[str, User] = {
    "TaroYamada": User(
        user_id="TaroYamada",
        password=hashlib.sha256("PaSswd4TY".encode("utf-8")).hexdigest(),
        nickname="たろー",
        comment="僕は元気です"
    )
}

app = FastAPI()
security = HTTPBasic()

# authenticator
def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    user_id = credentials.username
    password = hashlib.sha256(credentials.password.encode()).hexdigest()
    if user_id not in users or not secrets.compare_digest(users[user_id].password, password):
        return JSONResponse(status_code=401, content={"message": "Authentication Failed"})
    return user_id

# Debug
@app.get("/")
async def root():
    raise HTTPException(status_code=404, detail="Not Found")


@app.get("/users/{user_id}", response_model=UserDetailResponse)
async def get_user(user_id: str, authenticated_user: str = Depends(authenticate_user)):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if user_id != authenticated_user:
        raise HTTPException(status_code=403, detail="Permission denied")
    return UserDetailResponse(user=UserResponse(**users[user_id].model_dump()))

# add user
@app.post("/signup")
async def signup(request: SignupRequest, authenticated_user: str = Depends(authenticate_user)):
    # ✅ すでに user_id が登録されている場合
    if request.user_id in users:
        return JSONResponse(status_code=400, content={"message": "Account creation failed", "cause": "already same user_id is used"})
    # ✅ 必須項目のチェック
    if not request.user_id or not request.password:
        return JSONResponse(status_code=400, content={"message": "Account creation failed", "cause": "required user_id and password"})
    hashed_password = hashlib.sha256(request.password.encode()).hexdigest()
    new_user = User(
        user_id=request.user_id,
        password=hashed_password,
        nickname=request.nickname or request.user_id,
        comment=request.comment or ""
    )
    users[request.user_id] = new_user
    return JSONResponse(
        status_code=200,
        content={
            "message": "Account successfully created",
            "user": {
                "user_id": request.user_id,
                "nickname": request.nickname or request.user_id
            }
        }
    )

# update user
@app.patch("/users/{user_id}")
async def update_user(
    user_id: str,
    request: UserUpdateRequest,
    authenticated_user: str = Depends(authenticate_user)
):
    # ✅ 存在しないユーザーなら 404 を返す
    if user_id not in users:
        raise HTTPException(status_code=404, detail="No User found")
    # ✅ 他のユーザーの情報は更新不可
    if user_id != authenticated_user:
        raise HTTPException(status_code=403, detail="Permission denied")
    # ✅ 更新処理
    if request.nickname is not None:
        users[user_id].nickname = request.nickname
    if request.comment is not None:
        users[user_id].comment = request.comment
    # ✅ `user_id` や `password` を更新しようとした場合は 400 を返す
    if request.user_id is not None or request.password is not None:
        return JSONResponse(status_code=400, content={"message": "User update failed", "cause": "not updatable user_id and password"})
    return JSONResponse(
        status_code=200,
        content={
            "message": "User updated successfully",
            "user": {
                "user_id": user_id,
                "nickname": users[user_id].nickname,
                "comment": users[user_id].comment
            }
        }
    )

# delete user
@app.post("/close")
async def close_account(authenticated_user: str = Depends(authenticate_user)):
    # ✅ ユーザーが存在しない場合は 404 を返す
    if authenticated_user not in users:
        return JSONResponse(status_code=404, content={"message": "Account deletion failed", "cause": "User not found"})
    # ✅ ユーザーアカウントを削除
    del users[authenticated_user]
    return JSONResponse(
        status_code=200,
        content={"message": "Account deleted successfully"}
    )

