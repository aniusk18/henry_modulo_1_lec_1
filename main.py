from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from typing import List
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime as dt, timedelta, timezone
import os

fake_db = {"users": {}}

app = FastAPI()
access_token_expires = timedelta(minutes=30)

class User(BaseModel):
    username: str
    password: str
    email: str


class Payload(BaseModel):
    numbers: List[int]


class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

SECRET_KEY = os.environ.get("SECRET_KEY") or "your-secret-key"
ALGORITHM = "HS256"

def create_access_token(data: dict, expires_delta: timedelta = timedelta(hours=1)):
    to_encode = data.copy()
    expires = dt.now(timezone.utc) + timedelta(seconds=expires_delta)
    to_encode.update({"exp": expires})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    return token_data

@app.post("/simple_post")
def simple_post():
    return {"message": "OK"}

@app.post("/register")
def register(user: User):
    hashed_password = hash_password(user.password)
    fake_db["users"][user.username] = {"username": user.username, "password": hashed_password, "email": user.email}
    return {"message": "User created successfully"}

@app.post("/login")
async def login(user: User):
    if user.username in fake_db["users"] and verify_password(user.password, fake_db["users"][user.username]["password"]):
        access_token_expires = timedelta(minutes=30)
        access_token = create_access_token(data={"sub": user.username})
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

@app.get("/protected")
async def protected(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.username}!"}


@app.get("/")
def read_root():
    return {"Hello": "World"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)