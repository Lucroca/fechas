from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

# Configuración
SECRET_KEY = os.getenv("SECRET_KEY", "tu-clave-jwt-super-secreta-cambiame")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configuración de base de datos
DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "port": os.getenv("DB_PORT")
}

security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_user_from_db(username: str):
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, username, hashed_password, email, activo FROM usuarios WHERE username = %s AND activo = TRUE",
            (username,)
        )
        
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return user
        
    except Exception as e:
        print(f"Error getting user: {e}")
        return None

def update_last_access(username: str):
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE usuarios SET ultimo_acceso = CURRENT_TIMESTAMP WHERE username = %s",
            (username,)
        )
        
        conn.commit()
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"Error updating last access: {e}")

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido")
            
        # Verificar que el usuario aún existe y está activo
        user = get_user_from_db(username)
        if not user:
            raise HTTPException(status_code=401, detail="Usuario no válido")
            
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def authenticate_user(username: str, password: str):
    user = get_user_from_db(username)
    if not user or not pwd_context.verify(password, user["hashed_password"]):
        return False
    
    # Actualizar último acceso
    update_last_access(username)
    return user
