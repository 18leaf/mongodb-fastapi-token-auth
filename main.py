from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId
from jose import JWTError, jwt
from passlib.context import CryptContext
import motor.motor_asyncio

# secret key generate with $openssl -hex 32
SECRET_KEY = "long_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# add link to db and db name
MONGODB_URL = "url"
DATABASE_NAME = "database"

# Unique identifiers with mongo DB


class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")
# Define Models for token


class Token(BaseModel):
    access_token: str
    token_type: str


# TODO check that field != Field(alias="_id") add PyObjectId in case
class TokenData(BaseModel):
    user_id: str


class SignUpForm(BaseModel):
    username: str
    email: EmailStr | None = None
    password: str
# TODO => add any additional profile info: ie school, instrument(s) | look at replace BaseModel w/ UserModel so it is sent w/ it change accesibility


class UpdateUserInfo(BaseModel):
    username: str
    # .... same as UserModel
# define model of users' info to get from mongoDB


class UserModel(BaseModel):
    # define id for GET from db, mark id
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    username: str = Field(...)
    email: EmailStr | None = Field(default=None)
    disabled: bool | None = Field(default=False)  # Field(const=False)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        # extra = 'allow'
# Hidden from UserModel access by UserModelPassword(Usermodel) UserModel = data fetched from db


class UserInDB(UserModel):
    hashed_password: str = Field(...)

    class Config:
        extra = 'allow'


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/token")

app = FastAPI()
client = motor.motor_asyncio.AsyncIOMotorClient(MONGODB_URL)
db = client[DATABASE_NAME]


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


async def get_user(username: str):
    # ensure only 1 user with username exists
    count = await db["users"].count_documents({"username": username})
    # TODO improve multiple user function maybe eliminate possibility
    if count > 1:
        return None  # {"Error": "Many Users Found"}
    elif count == 0:
        return None  # {"Error": "No User Found"}
    # return user with matching username
    user_dict = await db["users"].find_one({"username": username})
    # convert to UserInDB class.. contains hasehd pw, unpacks contents of user and then unpacks their key value pairs
    return UserInDB(**user_dict)


async def get_user_by_id(user_id: str):
    # search by id if exists return, else pass, raise error
    if (user_dict := await db["users"].find_one({"_id": user_id})) is not None:
        return UserInDB(**user_dict)
    return None  # {"Error": "No User Found"}


async def authenticate_user(username: str, password: str):
    user = await get_user(username)

    # check if password matches with hashed password in db
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    # check if expired, if not set expireation to 30 mins away
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({'exp': expire})
    # return encoded token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    '''
    uses token, unpack user_id from token_data, checks db for user, if found returns model
    references: get_user_by_id

    ROLE -> Validate user credentials of token each time
    '''
    # define response on Error
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # unpack token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # sub is the user identity => _id in UserModel class
        user_id: str = payload.get("sub")
        if not user_id:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception
    user = await get_user_by_id(user_id=token_data.user_id)
    if not user:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: Annotated[UserModel, Depends(get_current_user)]):
    # check if user is disabled/
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive User Token")
    return current_user


@app.post("/api/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    ''' INFO ON /api/token Fetch Params
    SEND REQUEST *** needs the loginData as follows in body and headers
    const loginData = {
    grant_type: 'password',
    username: 'your_username',
    password: 'your_password',
    scope: ''
    };

    fetch('http://localhost:8000/token', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams(loginData)
    })

    RETURNS id, username, email, disabled
    '''
    user = await authenticate_user(username=form_data.username,
                                   password=form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/api/me/", response_model=UserModel)
async def read_user_me(current_user: Annotated[UserModel, Depends(get_current_active_user)]):
    return current_user


@app.post("/api/create_user")
async def create_user(user: UserInDB = Body(...)):
    # conv UserModel to JSON, POST to DB then GET/Read from db, return read user
    count = await db["users"].count_documents({"username": user.username})
    if count != 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists"
        )
    # hash their given password, then upload to database
    user.hashed_password = get_password_hash(user.hashed_password)
    user = jsonable_encoder(user)
    new_user = await db["users"].insert_one(user)
    created_user = await db["users"].find_one({"_id": new_user.inserted_id})

    # get token for created account (log user in)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    sub = new_user.inserted_id
    access_token = create_access_token(
        data={'sub': str(sub)}, expires_delta=access_token_expires
    )
    return {'user': created_user, 'access_token': access_token}
