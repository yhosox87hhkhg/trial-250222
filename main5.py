from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import JSONResponse
from fastapi import Request
from pydantic import BaseModel, Field, field_validator, ValidationError
import hashlib
import secrets
import re
from typing import Dict, Optional

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

# class SignupRequest(BaseModel):
#     user_id: str = Field(None, min_length=6, max_length=20)
#     password: str = Field(None, min_length=8, max_length=20)
#     nickname: Optional[str] = Field(None, max_length=30)
#     comment: Optional[str] = Field(None, max_length=100)
class SignupRequest(BaseModel):
    user_id: Optional[str] = Field(None, min_length=6, max_length=20)
    password: Optional[str] = Field(None, min_length=8, max_length=20)
    nickname: Optional[str] = Field(None, max_length=30)
    comment: Optional[str] = Field(None, max_length=100)
    # @field_validator("user_id")
    # @classmethod
    # def validate_user_id(cls, v: str) -> str:
    #     if not v:
    #         raise ValueError("user_id is required")
    #     if not re.match(r"^[a-zA-Z0-9]+$", v):
    #         raise ValueError("user_id must contain only alphanumeric characters")
    #     return v
    # @field_validator("password", mode="before")
    # @classmethod
    # def validate_password(cls, v: str) -> str:
    #     if not v:
    #         raise ValueError("password is required")
    #     if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).+$", v):
    #         raise ValueError("password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
    #     return v

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # すべてのオリジンを許可
    allow_credentials=True,
    allow_methods=["*"],  # すべてのメソッドを許可
    allow_headers=["*"],
)

def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    """通常の認証処理 (例: /users/{user_id}, /close など)"""
    user_id = credentials.username
    password = hashlib.sha256(credentials.password.encode()).hexdigest()
    if user_id not in users or not secrets.compare_digest(users[user_id].password, password):
        return JSONResponse(status_code=401, content={"message": "Authentication Failed"})   # 他のエンドポイントでは 401 を返す
    return user_id

def authenticate_user_signup(credentials: HTTPBasicCredentials = Depends(security)):
    """/signup 専用の認証処理 (失敗時は 400 Bad Request を返す)"""
    user_id = credentials.username
    password = hashlib.sha256(credentials.password.encode()).hexdigest()
    if user_id not in users or not secrets.compare_digest(users[user_id].password, password):
        return JSONResponse(status_code=400, content={"message": "Authentication Failed"})  # ✅ /signup は 400 を返す
    return user_id

# ** `/` は 404 にする **
@app.get("/")
async def root():
    raise HTTPException(status_code=404, detail="Not Found")

# ** ユーザー情報取得（認証必須）**
@app.get("/users/{user_id}", response_model=UserDetailResponse)
async def get_user(user_id: str, authenticated_user: str = Depends(authenticate_user)):
    if isinstance(authenticated_user, JSONResponse):  # 認証エラーの統一
        return authenticated_user
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if user_id != authenticated_user:
        raise HTTPException(status_code=403, detail="Permission denied")
    return UserDetailResponse(user=UserResponse(**users[user_id].model_dump()))

# ** サインアップ（認証不要）**
@app.post("/signup")
async def signup(request: SignupRequest):
    # ✅ user_id / password の必須チェック
    if not request.user_id or not request.password:
        return JSONResponse(status_code=400, content={
            "message": "Account creation failed",
            "cause": "required user_id and password"
        })

    if request.user_id in users:
        return JSONResponse(status_code=400, content={
            "message": "Account creation failed",
            "cause": "already same user_id is used"
        })

    hashed_password = hashlib.sha256(request.password.encode()).hexdigest()
    users[request.user_id] = User(
        user_id=request.user_id,
        password=hashed_password,
        nickname=request.nickname or request.user_id,
        comment=request.comment or ""
    )

    return JSONResponse(status_code=200, content={
        "message": "Account successfully created",
        "user": {
            "user_id": request.user_id,
            "nickname": request.nickname or request.user_id
        }
    })



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


# ** アカウント削除（認証必須）**
@app.post("/close")
async def close_account(authenticated_user: str = Depends(authenticate_user)):
    if isinstance(authenticated_user, JSONResponse):  # 認証エラーの統一
        return authenticated_user
    if authenticated_user not in users:
        return JSONResponse(status_code=404, content={"message": "Account deletion failed", "cause": "User not found"})
    
    del users[authenticated_user]
    return JSONResponse(status_code=200, content={"message": "Account deleted successfully"})

