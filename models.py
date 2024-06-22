
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import ForeignKey
from typing import List

from app import db


class User(db.Model):
    __tablename__ = 'users'
    user_id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(unique=True)
    password: Mapped[str] = mapped_column(unique=True)
    email: Mapped[str] = mapped_column(unique=True, nullable=True)
    logins = relationship('Login', back_populates='user', cascade="all, delete-orphan")
    role: Mapped['Role'] = relationship(back_populates="user")


    def __str__(self):
      return self.name

class Role(db.Model):
    __tablename__ = 'roles'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.user_id"))
    user: Mapped['User'] = relationship(back_populates='role')

    def __str__(self):
      return self.name

class Login(db.Model):
    __tablename__ = 'logins'
    login_id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.user_id', ondelete="CASCADE"))
    portal_name: Mapped[str] = mapped_column()
    login_name: Mapped[str] = mapped_column()
    login_password: Mapped[bytes] = mapped_column()
    user = relationship('User', back_populates='logins')
    
    def __str__(self):
      return self.portal_name