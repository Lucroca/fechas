from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import date
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="API Fechas Bloqueo", version="1.0.0")

# Configuración de base de datos desde variables de entorno
DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "port": os.getenv("DB_PORT")
}

# Modelo para crear fecha de bloqueo
class FechaBloqueo(BaseModel):
    idCentro: int
    Centro: str
    fechab: date

@app.get("/")
def root():
    return {"message": "API Fechas Bloqueo funcionando"}

@app.get("/health")
def health_check():
    return {"status": "OK", "database": "connected"}

# Obtener todas las fechas bloqueadas
@app.get("/fechas-bloqueo")
def obtener_fechas_bloqueo():
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM fecha_bloqueo ORDER BY fechab DESC")
        fechas = cursor.fetchall()

        cursor.close()
        conn.close()
        return {"status": "success", "fechas_bloqueo": fechas}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Obtener fechas bloqueadas por centro
@app.get("/fechas-bloqueo/centro/{id_centro}")
def obtener_fechas_por_centro(id_centro: int):
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM fecha_bloqueo WHERE idCentro = %s ORDER BY fechab DESC", (id_centro,))
        fechas = cursor.fetchall()
        
        cursor.close()
        conn.close()
        return {"status": "success", "fechas_bloqueo": fechas}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Crear nueva fecha de bloqueo
@app.post("/fechas-bloqueo")
def crear_fecha_bloqueo(fecha_bloqueo: FechaBloqueo):
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
        return {"status": "success", "fecha_bloqueo": nueva_fecha}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Eliminar fecha de bloqueo específica
@app.delete("/fechas-bloqueo/{id_centro}/{fecha}")
def eliminar_fecha_bloqueo(id_centro: int, fecha: date):
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
        return {"status": "success", "message": "Fecha de bloqueo eliminada"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Verificar si una fecha está bloqueada para un centro
@app.get("/fechas-bloqueo/verificar/{id_centro}/{fecha}")
def verificar_fecha_bloqueada(id_centro: int, fecha: date):
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
            "detalles": resultado if bloqueada else None
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
class MoverTodasFechas(BaseModel):
    nueva_fecha: date

@app.put("/fechas-bloqueo/mover-todas")
def mover_todas_fechas(datos: MoverTodasFechas):
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
            "fechas_actualizadas": fechas_actualizadas
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
