from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from datetime import date
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from dotenv import load_dotenv
from auth import verify_token, create_access_token, authenticate_user

load_dotenv()

app = FastAPI(title="API Fechas Bloqueo Segura", version="1.0.0")

# Configuración de base de datos desde variables de entorno
DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "port": os.getenv("DB_PORT")
}

# Modelos
class FechaBloqueo(BaseModel):
    idCentro: int
    Centro: str
    fechab: date

class LoginData(BaseModel):
    username: str
    password: str

class MoverTodasFechas(BaseModel):
    nueva_fecha: date

class CrearUsuario(BaseModel):
    username: str
    password: str
    email: str

class CambiarPassword(BaseModel):
    password_actual: str
    password_nueva: str

class ActivarDesactivarUsuario(BaseModel):
    activo: bool

# Endpoints públicos (sin autenticación)
@app.get("/")
def root():
    return {"message": "API Fechas Bloqueo funcionando - Requiere autenticación"}

@app.get("/health")
def health_check():
    return {"status": "OK", "message": "Servicio funcionando"}

# Endpoint de login
@app.post("/login")
def login(login_data: LoginData):
    user = authenticate_user(login_data.username, login_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    
    access_token = create_access_token(data={"sub": user["username"]})
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "expires_in_minutes": 30,
        "user": user["username"]
    }

# ENDPOINTS DE GESTIÓN DE USUARIOS

@app.post("/usuarios")
def crear_usuario(nuevo_usuario: CrearUsuario, current_user: str = Depends(verify_token)):
    # Solo admin puede crear usuarios
    if current_user != "admin":
        raise HTTPException(status_code=403, detail="No tienes permisos para crear usuarios")
    
    try:
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        hashed_password = pwd_context.hash(nuevo_usuario.password)
        
        cursor.execute(
            "INSERT INTO usuarios (username, hashed_password, email) VALUES (%s, %s, %s) RETURNING id, username, email, fecha_creacion",
            (nuevo_usuario.username, hashed_password, nuevo_usuario.email)
        )
        
        user_created = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()
        
        return {"status": "success", "usuario": user_created, "created_by": current_user}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/usuarios")
def listar_usuarios(current_user: str = Depends(verify_token)):
    # Solo admin puede ver usuarios
    if current_user != "admin":
        raise HTTPException(status_code=403, detail="No tienes permisos para ver usuarios")
    
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, email, activo, fecha_creacion, ultimo_acceso FROM usuarios ORDER BY fecha_creacion DESC")
        usuarios = cursor.fetchall()
        
        cursor.close()
        conn.close()
        return {"status": "success", "usuarios": usuarios}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.put("/usuarios/{username}/password")
def cambiar_password(username: str, cambio_password: CambiarPassword, current_user: str = Depends(verify_token)):
    # Solo el mismo usuario o admin puede cambiar contraseña
    if current_user != username and current_user != "admin":
        raise HTTPException(status_code=403, detail="No tienes permisos para cambiar esta contraseña")
    
    try:
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        # Si no es admin, verificar contraseña actual
        if current_user != "admin":
            cursor.execute("SELECT hashed_password FROM usuarios WHERE username = %s", (username,))
            user_data = cursor.fetchone()
            
            if not user_data or not pwd_context.verify(cambio_password.password_actual, user_data["hashed_password"]):
                raise HTTPException(status_code=400, detail="Contraseña actual incorrecta")
        
        # Cambiar contraseña
        new_hashed_password = pwd_context.hash(cambio_password.password_nueva)
        cursor.execute(
            "UPDATE usuarios SET hashed_password = %s WHERE username = %s",
            (new_hashed_password, username)
        )
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return {"status": "success", "message": "Contraseña actualizada", "updated_by": current_user}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.put("/usuarios/{username}/estado")
def cambiar_estado_usuario(username: str, estado: ActivarDesactivarUsuario, current_user: str = Depends(verify_token)):
    # Solo admin puede activar/desactivar usuarios
    if current_user != "admin":
        raise HTTPException(status_code=403, detail="No tienes permisos para cambiar el estado de usuarios")
    
    # No permitir desactivar al propio admin
    if username == "admin" and not estado.activo:
        raise HTTPException(status_code=400, detail="No puedes desactivar el usuario admin")
    
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE usuarios SET activo = %s WHERE username = %s RETURNING id, username, activo",
            (estado.activo, username)
        )
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        updated_user = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()
        
        accion = "activado" if estado.activo else "desactivado"
        return {"status": "success", "message": f"Usuario {accion}", "usuario": updated_user, "updated_by": current_user}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.delete("/usuarios/{username}")
def eliminar_usuario(username: str, current_user: str = Depends(verify_token)):
    # Solo admin puede eliminar usuarios
    if current_user != "admin":
        raise HTTPException(status_code=403, detail="No tienes permisos para eliminar usuarios")
    
    # No permitir eliminar al admin
    if username == "admin":
        raise HTTPException(status_code=400, detail="No puedes eliminar el usuario admin")
    
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM usuarios WHERE username = %s", (username,))
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return {"status": "success", "message": f"Usuario {username} eliminado", "deleted_by": current_user}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ENDPOINTS DE FECHAS DE BLOQUEO

@app.get("/fechas-bloqueo")
def obtener_fechas_bloqueo(current_user: str = Depends(verify_token)):
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM fecha_bloqueo ORDER BY fechab DESC")
        fechas = cursor.fetchall()
        
        cursor.close()
        conn.close()
        return {"status": "success", "fechas_bloqueo": fechas, "user": current_user}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/fechas-bloqueo/centro/{id_centro}")
def obtener_fechas_por_centro(id_centro: int, current_user: str = Depends(verify_token)):
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM fecha_bloqueo WHERE idCentro = %s ORDER BY fechab DESC", (id_centro,))
        fechas = cursor.fetchall()
        
        cursor.close()
        conn.close()
        return {"status": "success", "fechas_bloqueo": fechas, "user": current_user}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/fechas-bloqueo")
def crear_fecha_bloqueo(fecha_bloqueo: FechaBloqueo, current_user: str = Depends(verify_token)):
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO fecha_bloqueo (idCentro, Centro, fechab) VALUES (%s, %s, %s) RETURNING *",
            (fecha_bloqueo.idCentro, fecha_bloqueo.Centro, fecha_bloqueo.fechab)
        )
        
        nueva_fecha = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()
        return {"status": "success", "fecha_bloqueo": nueva_fecha, "created_by": current_user}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.delete("/fechas-bloqueo/{id_centro}/{fecha}")
def eliminar_fecha_bloqueo(id_centro: int, fecha: date, current_user: str = Depends(verify_token)):
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        cursor.execute(
            "DELETE FROM fecha_bloqueo WHERE idCentro = %s AND fechab = %s",
            (id_centro, fecha)
        )
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Fecha de bloqueo no encontrada")
        
        conn.commit()
        cursor.close()
        conn.close()
        return {"status": "success", "message": "Fecha de bloqueo eliminada", "deleted_by": current_user}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/fechas-bloqueo/verificar/{id_centro}/{fecha}")
def verificar_fecha_bloqueada(id_centro: int, fecha: date, current_user: str = Depends(verify_token)):
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM fecha_bloqueo WHERE idCentro = %s AND fechab = %s",
            (id_centro, fecha)
        )
        
        resultado = cursor.fetchone()
        cursor.close()
        conn.close()
        
        bloqueada = resultado is not None
        return {
            "status": "success", 
            "fecha_bloqueada": bloqueada,
            "detalles": resultado if bloqueada else None,
            "checked_by": current_user
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.put("/fechas-bloqueo/mover-todas")
def mover_todas_fechas(datos: MoverTodasFechas, current_user: str = Depends(verify_token)):
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE fecha_bloqueo SET fechab = %s RETURNING *",
            (datos.nueva_fecha,)
        )
        
        fechas_actualizadas = cursor.fetchall()
        filas_afectadas = cursor.rowcount
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return {
            "status": "success", 
            "mensaje": f"Se movieron {filas_afectadas} fechas a {datos.nueva_fecha}",
            "fechas_actualizadas": fechas_actualizadas,
            "updated_by": current_user
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
