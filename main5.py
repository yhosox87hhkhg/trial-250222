from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import JSONResponse
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

class SignupRequest(BaseModel):
    user_id: str = Field(None, min_length=6, max_length=20)
    password: str = Field(None, min_length=8, max_length=20)
    nickname: Optional[str] = Field(None, max_length=30)
    comment: Optional[str] = Field(None, max_length=100)
    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        if not v:
            raise ValueError("user_id is required")
        if not re.match(r"^[a-zA-Z0-9]+$", v):
            raise ValueError("user_id must contain only alphanumeric characters")
        return v
    @field_validator("password", mode="before")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not v:
            raise ValueError("password is required")
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).+$", v):
            raise ValueError("password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
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

# ** 認証処理 **
def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    user_id = credentials.username
    password = hashlib.sha256(credentials.password.encode()).hexdigest() 
    if user_id not in users or not secrets.compare_digest(users[user_id].password, password):
        return JSONResponse(status_code=400, content={"message": "Authentication Failed"})
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
    # body = await request.body()
    # print(f"Received request: {body.decode('utf-8')}") # debug
    try:
        body = await request.body()
        request._body = body  # `_body` に保存して再利用可能に
        print(f"Received request: {body.decode('utf-8')}")  # デバッグ用
    except Exception as e:
        print(f"Error reading request body: {str(e)}")  # エラーハンドリング
    try:
        # Pydantic バリデーション実行
        request = SignupRequest.model_validate(request)
    except ValidationError as e:
        # バリデーションエラーを 400 に変換
        return JSONResponse(status_code=400, content={
            "message": "Account creation failed",
            "cause": e.errors()[0]['msg']  # 最初のエラーのメッセージを取得
        })
    # ✅ すでに user_id が登録されている場合
    if request.user_id in users:
        return JSONResponse(status_code=400, content={"message": "Account creation failed", "cause": "already same user_id is used"})
    # ✅ 必須項目のチェックを行い 400 エラーを明示的に返す
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

# ** アカウント削除（認証必須）**
@app.post("/close")
async def close_account(authenticated_user: str = Depends(authenticate_user)):
    if isinstance(authenticated_user, JSONResponse):  # 認証エラーの統一
        return authenticated_user
    if authenticated_user not in users:
        return JSONResponse(status_code=404, content={"message": "Account deletion failed", "cause": "User not found"})
    
    del users[authenticated_user]
    return JSONResponse(status_code=200, content={"message": "Account deleted successfully"})

