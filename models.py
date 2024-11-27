from typing import List
from pydantic import BaseModel

class User(BaseModel):
    username: str
    password: str
    email: str

class Payload(BaseModel):
    numbers: List[int]

class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int