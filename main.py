from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import OAuth2PasswordBearer
from typing import List
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt,JWTError
from datetime import datetime, timedelta

# Also add these constants if not already defined
SECRET_KEY = "123456"  # In production use a secure secret key
ALGORITHM = "HS256"
fake_db = {"users": {}}

app = FastAPI()



pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")




class User(BaseModel):
    username: str
    password: str

class Payload(BaseModel):
    numbers: List[int]


class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int



pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
#
""" Verifies a plain-text password against a hashed password using the bcrypt algorithm.
    
    Args:
        plain_password (str): The plain-text password to verify.
        hashed_password (str): The hashed password to compare against.
    
    Returns:
        bool: True if the plain-text password matches the hashed password, False otherwise. """
def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)


"""
    Creates a JWT access token with the provided data and an optional expiration time.
    
    Args:
        data (dict): A dictionary containing the data to be encoded in the JWT token.
        expires_delta (timedelta, optional): The time delta after which the token should expire. If not provided, the token will expire in 15 minutes.
    
    Returns:
        str: The encoded JWT access token.
    """
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

""" Retrieves the current user from the provided JWT token.
    
    Args:
        token (str): The JWT token containing the user information.
    
    Returns:
        dict: A dictionary containing the username of the current user.
    
    Raises:
        HTTPException: If the token is invalid or the username is not present in the token. """
def get_current_user(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="401: Credenciales Inválidas / Autorización fállida.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return {"username": username}
    except JWTError:
        raise credentials_exception


"""
    Hashes the provided password using the password hashing context.
    
    Args:
        password (str): The password to be hashed.
    
    Returns:
        str: The hashed password.
    """
def hash_password(password: str) -> str:

        return pwd_context.hash(password)
""" Registers a new user in the application.

Args:
    user (User): The user object containing the username and password.

Raises:
    HTTPException: If the username already exists in the database.

Returns:
    dict: A message indicating that the user was created successfully. """
@app.post("/register")
def register(user: User):
    if user.username in fake_db["users"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    hashed_password = hash_password(user.password)
    fake_db["users"][user.username] = {"username": user.username, "password": hashed_password}
    return {"message": "User created successfully"}

""" Authenticates a user and generates an access token.

Args:
    user (User): The user object containing the username and password.

Raises:
    HTTPException: If the username or password is incorrect.

Returns:
    dict: A dictionary containing the access token and token type. """
@app.post("/login")
async def login(user: User):
    if user.username in fake_db["users"] and verify_password(user.password, fake_db["users"][user.username]["password"]):
        access_token_expires = timedelta(minutes=30)
        access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=400, detail="Incorrect username or password")


"""
Applies the bubble sort algorithm to the provided list of numbers.

Args:
    payload (Payload): An object containing the list of numbers to be sorted.
    token (str): The authentication token for the current user.

Returns:
    dict: A dictionary containing the sorted list of numbers.

Raises:
    HTTPException:
        - If the authentication token is missing, with a 401 Unauthorized status code.
        - If the authentication token is invalid, with a 401 Unauthorized status code.
"""
@app.post("/bubble-sort")
async def bubble_sort(payload: Payload, token: str = Query(..., description="Authentication token")):
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        current_user = get_current_user(token)
        numbers = payload.numbers.copy()
        n = len(numbers)
        for i in range(n):
            for j in range(0, n - i - 1):
                if numbers[j] > numbers[j + 1]:
                    numbers[j], numbers[j + 1] = numbers[j + 1], numbers[j]
        return {"numbers": numbers}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

"""
Filters the provided list of numbers to return only the even numbers.

Args:
    payload (Payload): An object containing the list of numbers to be filtered.
    token (str): The authentication token for the current user.

Returns:
    dict: A dictionary containing the list of even numbers.

Raises:
    HTTPException:
        - If the authentication token is missing, with a 401 Unauthorized status code.
        - If the authentication token is invalid, with a 401 Unauthorized status code.
"""
@app.post("/filter-even")
async def filter_even(payload: Payload, token: str = Query(..., description="Authentication token")):
    try:
        current_user = get_current_user(token)
        even_numbers = [num for num in payload.numbers if num % 2 == 0]
        return {"even_numbers": even_numbers}
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

"""
Calculates the sum of the numbers provided in the payload.

Args:
    payload (Payload): An object containing the list of numbers to be summed.
    token (str): The authentication token for the current user.

Returns:
    dict: A dictionary containing the sum of the numbers.

Raises:
    HTTPException:
        - If the authentication token is invalid or missing, with a 401 Unauthorized status code.
"""
@app.post("/sum-elements")
async def sum_elements(payload: Payload, token: str = Query(..., description="Authentication token")):
    try:
        current_user = get_current_user(token)
        total_sum = sum(payload.numbers)
        return {"sum": total_sum}
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )


"""
Calculates the maximum value from the list of numbers provided in the payload.

Args:
    payload (Payload): An object containing the list of numbers.
    token (str): The authentication token for the current user.

Returns:
    dict: A dictionary containing the maximum value from the list of numbers.

Raises:
    HTTPException:
        - If the authentication token is invalid or missing, with a 401 Unauthorized status code.
"""
@app.post("/max-value")
async def max_value(payload: Payload, token: str = Query(..., description="Authentication token")):
    try:
        current_user = get_current_user(token)
        max_number = max(payload.numbers)
        return {"max": max_number}
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )



"""
Performs a binary search on the provided list of numbers to find the target value.

Args:
    payload (BinarySearchPayload): An object containing the list of numbers and the target value to search for.
    token (str): The authentication token for the current user.

Returns:
    dict: A dictionary containing the result of the binary search, with keys "found" (boolean) and "index" (integer).

Raises:
    HTTPException:
        - If the authentication token is invalid or missing, with a 401 Unauthorized status code.
"""
@app.post("/binary-search")
async def binary_search(payload: BinarySearchPayload, token: str = Query(..., description="Authentication token")):
    try:
        current_user = get_current_user(token)
        numbers = sorted(payload.numbers)
        target = payload.target
        left, right = 0, len(numbers) - 1
        
        while left <= right:
            mid = (left + right) // 2
            if numbers[mid] == target:
                return {"found": True, "index": mid}
            elif numbers[mid] < target:
                left = mid + 1
            else:
                right = mid - 1
                
        return {"found": False, "index": -1}
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/")
def read_root():
    return {"Hello": "World"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)



