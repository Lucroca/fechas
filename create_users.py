from passlib.context import CryptContext
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from dotenv import load_dotenv

load_dotenv()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "port": os.getenv("DB_PORT")
}

def crear_usuarios_iniciales():
    usuarios = [
        {"username": "admin", "password": "admin123", "email": "admin@empresa.com"},
        {"username": "usuario", "password": "user456", "email": "usuario@empresa.com"},
        {"username": "manager", "password": "manager789", "email": "manager@empresa.com"}
    ]
    
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        for user in usuarios:
            hashed_password = pwd_context.hash(user["password"])
            
            cursor.execute("""
                INSERT INTO usuarios (username, hashed_password, email) 
                VALUES (%s, %s, %s) 
                ON CONFLICT (username) DO NOTHING
            """, (user["username"], hashed_password, user["email"]))
            
        conn.commit()
        cursor.close()
        conn.close()
        print("Usuarios creados exitosamente")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    crear_usuarios_iniciales()

