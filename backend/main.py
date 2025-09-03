from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

# ----------------------------
# App Setup
# ----------------------------
app = FastAPI(title="AfterMe Backend", version="2.0.0")

# Security
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ----------------------------
# Database Setup
# ----------------------------
DATABASE_URL = "sqlite:///./afterme.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ----------------------------
# Models (DB)
# ----------------------------
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    memories = relationship("MemoryDB", back_populates="owner")

class MemoryDB(Base):
    __tablename__ = "memories"
    id = Column(Integer, primary_key=True, index=True)
    text = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("UserDB", back_populates="memories")

Base.metadata.create_all(bind=engine)

# ----------------------------
# Schemas (Pydantic)
# ----------------------------
class User(BaseModel):
    username: str
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class Memory(BaseModel):
    text: str
    timestamp: Optional[datetime] = None

class MemoryUpdate(BaseModel):
    text: str

# ----------------------------
# Auth Helpers
# ----------------------------
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str, db: Session):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def root():
    return {"message": "Welcome to AfterMe Backend (SQLite ready)!"}

@app.post("/register")
def register(user: User, db: Session = Depends(get_db)):
    if db.query(UserDB).filter(UserDB.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed = get_password_hash(user.password)
    new_user = UserDB(username=user.username, email=user.email, hashed_password=hashed)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
def login(user: User, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": db_user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/me")
def read_users_me(token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    return {"username": user.username, "email": user.email}

# ----------------------------
# Memory System
# ----------------------------
@app.post("/remember")
def remember(memory: Memory, token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    new_memory = MemoryDB(text=memory.text, owner_id=user.id)
    db.add(new_memory)
    db.commit()
    db.refresh(new_memory)
    return {"message": "Memory saved", "memory": new_memory.text}

@app.get("/memories")
def get_memories(token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    return {"memories": [{"id": m.id, "text": m.text, "timestamp": m.timestamp} for m in user.memories]}

@app.put("/memory/{memory_id}")
def update_memory(memory_id: int, memory_update: MemoryUpdate, token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    memory = db.query(MemoryDB).filter(MemoryDB.id == memory_id, MemoryDB.owner_id == user.id).first()
    if not memory:
        raise HTTPException(status_code=404, detail="Memory not found")
    memory.text = memory_update.text
    db.commit()
    db.refresh(memory)
    return {"message": "Memory updated", "memory": memory.text}

@app.delete("/memory/{memory_id}")
def delete_memory(memory_id: int, token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    memory = db.query(MemoryDB).filter(MemoryDB.id == memory_id, MemoryDB.owner_id == user.id).first()
    if not memory:
        raise HTTPException(status_code=404, detail="Memory not found")
    db.delete(memory)
    db.commit()
    return {"message": "Memory deleted", "deleted_id": memory_id}

# ----------------------------
# AI Talk (basic)
# ----------------------------
@app.post("/talk")
def talk(query: str, token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    user_memories = user.memories
    if not user_memories:
        return {"reply": "I don't know much yet. Please share some memories!"}
    for mem in reversed(user_memories):
        if any(word in query.lower() for word in mem.text.lower().split()):
            return {"reply": f"From what I recall: {mem.text}"}
    return {"reply": "I remember you, but nothing matches this question."}
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

# ----------------------------
# App Setup
# ----------------------------
app = FastAPI(title="AfterMe Backend", version="2.0.0")

# Security
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ----------------------------
# Database Setup
# ----------------------------
DATABASE_URL = "sqlite:///./afterme.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ----------------------------
# Models (DB)
# ----------------------------
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    memories = relationship("MemoryDB", back_populates="owner")

class MemoryDB(Base):
    __tablename__ = "memories"
    id = Column(Integer, primary_key=True, index=True)
    text = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("UserDB", back_populates="memories")

Base.metadata.create_all(bind=engine)

# ----------------------------
# Schemas (Pydantic)
# ----------------------------
class User(BaseModel):
    username: str
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class Memory(BaseModel):
    text: str
    timestamp: Optional[datetime] = None

class MemoryUpdate(BaseModel):
    text: str

# ----------------------------
# Auth Helpers
# ----------------------------
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str, db: Session):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def root():
    return {"message": "Welcome to AfterMe Backend (SQLite ready)!"}

@app.post("/register")
def register(user: User, db: Session = Depends(get_db)):
    if db.query(UserDB).filter(UserDB.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed = get_password_hash(user.password)
    new_user = UserDB(username=user.username, email=user.email, hashed_password=hashed)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
def login(user: User, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": db_user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/me")
def read_users_me(token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    return {"username": user.username, "email": user.email}

# ----------------------------
# Memory System
# ----------------------------
@app.post("/remember")
def remember(memory: Memory, token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    new_memory = MemoryDB(text=memory.text, owner_id=user.id)
    db.add(new_memory)
    db.commit()
    db.refresh(new_memory)
    return {"message": "Memory saved", "memory": new_memory.text}

@app.get("/memories")
def get_memories(token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    return {"memories": [{"id": m.id, "text": m.text, "timestamp": m.timestamp} for m in user.memories]}

@app.put("/memory/{memory_id}")
def update_memory(memory_id: int, memory_update: MemoryUpdate, token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    memory = db.query(MemoryDB).filter(MemoryDB.id == memory_id, MemoryDB.owner_id == user.id).first()
    if not memory:
        raise HTTPException(status_code=404, detail="Memory not found")
    memory.text = memory_update.text
    db.commit()
    db.refresh(memory)
    return {"message": "Memory updated", "memory": memory.text}

@app.delete("/memory/{memory_id}")
def delete_memory(memory_id: int, token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    memory = db.query(MemoryDB).filter(MemoryDB.id == memory_id, MemoryDB.owner_id == user.id).first()
    if not memory:
        raise HTTPException(status_code=404, detail="Memory not found")
    db.delete(memory)
    db.commit()
    return {"message": "Memory deleted", "deleted_id": memory_id}

# ----------------------------
# AI Talk (basic)
# ----------------------------
@app.post("/talk")
def talk(query: str, token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    user_memories = user.memories
    if not user_memories:
        return {"reply": "I don't know much yet. Please share some memories!"}
    for mem in reversed(user_memories):
        if any(word in query.lower() for word in mem.text.lower().split()):
            return {"reply": f"From what I recall: {mem.text}"}
    return {"reply": "I remember you, but nothing matches this question."}
