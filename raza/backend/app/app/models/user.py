from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Column, Integer, String
from sqlalchemy.orm import relationship

from app.db.base_class import Base

if TYPE_CHECKING:
    from .item import Item  # noqa: F401


class User(Base):
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean(), default=True)
    is_superuser = Column(Boolean(), default=False)
    items = relationship("Item", back_populates="owner")


@classmethod
def generate_password(cls, email: str) -> str:
    user = cls.get(email=email)

    if not user:
        return None

    if user.password_set:
        return None

    user.login_retry = 0
    user.password_expire = datetime.now() + timedelta(hours=1)
    password = random_n_words()
    user.hashed_password = pwd_context.hash(password)
    return password


def verify_password(self, password: str) -> bool:

    if not self.hashed_password:
        return False

    if self.password_expire and self.password_expire < datetime.now():
        return False

    return pwd_context.verify(password, self.hashed_password)
