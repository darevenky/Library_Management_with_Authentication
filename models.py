from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Date, func
from database import Base, engine
from sqlalchemy.orm import relationship
from datetime import datetime
def create_tables():
    Base.metadata.create_all(engine)



class User(Base):
    __tablename__='User'

    username = Column(String(50), primary_key=True)
    fullname = Column(String(50))
    password = Column(String(200))
    role = Column(String(10))
    
    user1 = relationship("Library", back_populates="user")


class Book(Base):
    __tablename__='Book'

    book_id = Column(Integer, primary_key=True, autoincrement=True)
    book_name = Column(String(200))
    author = Column(String(100))

    book1 = relationship("Library", back_populates="book")


class Library(Base):
    __tablename__='Library'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), ForeignKey("User.username", ondelete="CASCADE"))
    book_id = Column(Integer, ForeignKey("Book.book_id", ondelete="CASCADE"))
    book_name = Column(String(200))
    issue_date = Column(Date, default=func.current_date())
    return_date = Column(Date, nullable=True)
    

    user = relationship("User", back_populates="user1")
    book = relationship("Book", back_populates="book1")