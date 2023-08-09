from datetime import datetime, timedelta, date
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from database import SessionLocal
import models  
from sqlalchemy.orm import sessionmaker, Session


        # database section started

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "postgresql://postgres:root@localhost/project1"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

            # database section ended



SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):

    fullname : str
    username : str
    password :str
    role : str 
    
class Book(BaseModel):
    book_id : int
    book_name : str
    author : str

class Library(BaseModel):
    book_id : int
    book_name : str
    

class Update_Library(BaseModel):
    book_id : int
    return_date : date


class User_book_details(BaseModel):
    book_name : str
    author : str
    issue_date : date
    return_date : date | None = None

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)



db = SessionLocal()
app = FastAPI(title = 'JWTAuthenticatione with Library')


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return {'Error': 'user is not in database'}
        token_data = TokenData(username=username)
    except JWTError:
        return {'Error': 'authentication error occured'}
    user =  db.query(models.User).filter(models.User.username == token_data.username).first()

    if user is None:
        return {'Error': 'user is not in database'}
    return user

async def get_current_active_user( current_user: Annotated[User, Depends(get_current_user)]):
    if not current_user:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def authenticate_user(db1, username: str, password: str):
    user =  db.query(models.User).filter(models.User.username == username).first()

    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

                  
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(db, form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
            )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}
 

@app.post('/register')
def register(reg:User):


    user0 = db.query(models.User).filter(models.User.username == reg.username).first()

    if user0:
        return {'message': 'the given username is already existed'}
    else:
        pass

    user = db.query(models.User).filter(models.User.fullname==reg.fullname)

    user1 = [i.fullname for i in user]
    rol = [i.role for i in user]

    
    if user:
        for a in rol:
            if a == reg.role:
                return {'message': 'the given fullname with role is already existed'}
            else:
                pass
    else:
        pass


    hashed_password = get_password_hash(reg.password)

    user2 = models.User(
        fullname = reg.fullname,
        username = reg.username,
        password = hashed_password,
        role = reg.role.lower()
        )
    db.add(user2)
    db.commit()
    return {"message": f"User registered successfully with {reg.username}"}



@app.post('/AddBook' )
def Addbook(book:Book, current_user: Annotated[User, Depends(get_current_active_user)]):

    if current_user.role=='user':
        return {'error': 'only admin can add new book, pls contact him'}

    bk_id = db.query(models.Book).filter(models.Book.book_id == book.book_id).first()
    
    if bk_id:
        raise HTTPException(status_code=409,detail='Book id  is already existed, pls check the books list')
    

    bk_nm = db.query(models.Book).filter(models.Book.book_name==book.book_name)


    books = [i.book_name for i in bk_nm]
    authors = [i.author for i in bk_nm]


    if bk_nm:
        for a in range(len(books)):
            if books[a] == book.book_name and  authors[a] == book.author:
                return {'message': 'the given bookname with author is already existed'}
            else:
                pass
    else:
        pass
    
    book3 = models.Book(
        book_id = book.book_id,
        book_name = book.book_name,
        author = book.author
    )
    
    db.add(book3)
    db.commit()
    return {'message': f'New book is added with name of {book.book_name}'}


@app.get('/all books')
def all_books():
    books = db.query(models.Book).all()
    if not books:
        return {'message': 'No books in library'}
    else:
        return books


@app.post('/take_book')
def take_book(lib:Library, current_user: Annotated[User, Depends(get_current_active_user)]):

    user = db.query(models.User).filter(models.User.username == current_user.username).first()

    if not user:
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
            )
    
    if current_user.role=='admin':
        return {'error': 'only users are allowed to take books'}
    
     
    library1 = db.query(models.Library).filter(models.Library.username == current_user.username)
    li = [i.book_id for i in library1]
    print(li)
    if library1:
        for a in li:
            if a == lib.book_id:
                print(a)
                return {'message': 'book_id you have entered is already issued once'}
    


    library = db.query(models.Book).filter(models.Book.book_id == lib.book_id).first()
    if not library:
        return {'message': 'the book_id you have entered is  not found in Library'}

    if library.book_name != lib.book_name:
        return {'message': 'the book you have entered is  not found in Library'}


    library = models.Library(
        book_id = lib.book_id,
        book_name = lib.book_name,
        username = current_user.username,
        
    )

    db.add(library)
    db.commit()

    return {'message': f' {lib.book_name} book is issued'}


@app.post('/return_book')
def return_book(lib: Update_Library, current_user: Annotated[User, Depends(get_current_active_user)]):

    
    library1 = db.query(models.Library).filter(models.Library.username == current_user.username).first()

    if library1:
        if library1.book_id == lib.book_id:
            if not lib.return_date:
                library1.return_date = datetime.now().date()
            else:
                library1.return_date = lib.return_date  

            db.commit()
            return {'message': 'book is updated'}
        else:
            return {'error': 'the id you have entered is wrong'}



@app.get("/my/books/")
async def my_books(current_user: Annotated[User, Depends(get_current_active_user)]):

    result = db.query(models.Library,models.Book).join(models.Book).filter(models.Library.username == current_user.username).all()  

    books = [User_book_details(issue_date=item.Library.issue_date,return_date=item.Library.return_date , book_name=item.Book.book_name, author=item.Book.author) for item in result]
    
    if books:
        return books
    else:
        return {'message': 'currently you dont have any books'}