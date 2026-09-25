"""TournaData System - API REST (FastAPI + SQLAlchemy + MySQL)."""
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

DB_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root:root@localhost/tournadata?charset=utf8mb4")
SECRET = os.getenv("JWT_SECRET", "cambia-esto-en-produccion")
ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

# DB_SSL=true para MySQL en la nube (Aiven exige conexión cifrada)
_args = {"ssl": {"check_hostname": False}} if os.getenv("DB_SSL", "").lower() in ("1", "true") else {}
engine = create_engine(DB_URL, pool_size=5, max_overflow=5, pool_pre_ping=True, pool_recycle=280, connect_args=_args)


def q(c, sql, **p):
    return [dict(r) for r in c.execute(text(sql), p).mappings()]


def hash_pw(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


@asynccontextmanager
async def lifespan(app):
    # Usuarios iniciales (cambia las contraseñas con variables de entorno)
    with engine.begin() as c:
        if not q(c, "SELECT 1 FROM usuarios LIMIT 1"):
            for u, r, env, d in [("admin", "admin", "ADMIN_PASSWORD", "admin123"),
                                 ("arbitro1", "arbitro", "ARBITRO_PASSWORD", "arbitro123")]:
                c.execute(text("INSERT INTO usuarios (username,password_hash,rol) VALUES (:u,:h,:r)"),
                          {"u": u, "h": hash_pw(os.getenv(env, d)), "r": r})
    yield


app = FastAPI(title="TournaData System API", version="1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["*"], allow_headers=["*"])
oauth = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# ---------- Autenticación / roles ----------
@app.post("/api/v1/auth/login", tags=["auth"])
def login(f: OAuth2PasswordRequestForm = Depends()):
    with engine.connect() as c:
        u = q(c, "SELECT * FROM usuarios WHERE username=:u AND is_active=1", u=f.username)
    if not u or not bcrypt.checkpw(f.password.encode(), u[0]["password_hash"].encode()):
        raise HTTPException(401, "Usuario o contraseña incorrectos")
    exp = datetime.now(timezone.utc) + timedelta(hours=8)
    tok = jwt.encode({"sub": u[0]["username"], "rol": u[0]["rol"], "exp": exp}, SECRET, "HS256")
    return {"access_token": tok, "token_type": "bearer", "rol": u[0]["rol"]}


def require(*roles):
    def dep(token: str = Depends(oauth)):
        try:
            data = jwt.decode(token, SECRET, algorithms=["HS256"])
        except JWTError:
            raise HTTPException(401, "Token inválido o expirado")
        if data["rol"] not in roles:
            raise HTTPException(403, f"El rol '{data['rol']}' no tiene permiso para esta acción")
        return data
    return dep


# ---------- Lectura pública (rol Público: solo SELECT) ----------
@app.get("/api/v1/torneos", tags=["torneos"])
def torneos():
    with engine.connect() as c:
        return q(c, "SELECT * FROM torneos WHERE is_active=1 ORDER BY fecha_inicio DESC")


@app.get("/api/v1/brackets/{id_torneo}", tags=["torneos"])
def bracket(id_torneo: int):
    with engine.connect() as c:
        rows = q(c, """
          SELECT p.id_partido, f.nombre_fase, f.orden_jerarquico, p.estado, p.fecha_hora_juego,
                 p.marcador_local, p.marcador_visitante, p.ganador_id,
                 p.equipo_local_id, p.equipo_visitante_id, el.tag AS local, ev.tag AS visitante,
                 p.partido_origen_local_id, p.partido_origen_visita_id
          FROM partidos p JOIN fases_rondas f ON f.id_fase = p.id_fase
          LEFT JOIN equipos el ON el.id_equipo = p.equipo_local_id
          LEFT JOIN equipos ev ON ev.id_equipo = p.equipo_visitante_id
          WHERE f.id_torneo = :t ORDER BY f.orden_jerarquico, p.id_partido""", t=id_torneo)
    if not rows:
        raise HTTPException(404, "Torneo sin partidos")
    rondas = {}
    for r in rows:
        rondas.setdefault(r["nombre_fase"], []).append(r)
    return [{"fase": k, "partidos": v} for k, v in rondas.items()]


@app.get("/api/v1/partidos/{id_partido}", tags=["partidos"])
def partido(id_partido: int):
    with engine.connect() as c:
        p = q(c, "SELECT * FROM partidos WHERE id_partido=:i", i=id_partido)
        if not p:
            raise HTTPException(404, "Partido no encontrado")
        st = q(c, """SELECT j.gamertag, s.* FROM estadisticas_partido s
                     JOIN jugadores j ON j.id_jugador = s.id_jugador WHERE s.id_partido=:i""", i=id_partido)
    return {**p[0], "estadisticas": st}


@app.get("/api/v1/partidos/{id_partido}/roster", tags=["partidos"])
def roster(id_partido: int):
    """Jugadores de los dos equipos del partido (para capturar estadísticas)."""
    with engine.connect() as c:
        return q(c, """SELECT j.id_jugador, j.gamertag, e.id_equipo, e.tag
            FROM partidos p JOIN fases_rondas f ON f.id_fase = p.id_fase
            JOIN inscripciones_equipo i ON i.id_torneo = f.id_torneo
                 AND i.id_equipo IN (p.equipo_local_id, p.equipo_visitante_id)
            JOIN roster_torneo r ON r.id_inscripcion = i.id_inscripcion
            JOIN jugadores j ON j.id_jugador = r.id_jugador
            JOIN equipos e ON e.id_equipo = i.id_equipo
            WHERE p.id_partido = :i ORDER BY e.id_equipo, j.gamertag""", i=id_partido)


@app.get("/api/v1/torneos/{id_torneo}/posiciones", tags=["reportes"])
def posiciones(id_torneo: int):
    with engine.connect() as c:
        return q(c, """SELECT *, (gf - gc) AS dif FROM vista_tabla_posiciones
                       WHERE id_torneo=:t ORDER BY puntos DESC, dif DESC""", t=id_torneo)


@app.get("/api/v1/estadisticas/lideres", tags=["reportes"])
def lideres(limite: int = 10):
    with engine.connect() as c:
        return q(c, "SELECT * FROM vista_lideres_estadisticas LIMIT :n", n=limite)


@app.get("/api/v1/equipos/{a}/vs/{b}", tags=["reportes"])
def head_to_head(a: int, b: int):
    with engine.connect() as c:
        h = q(c, """SELECT * FROM partidos WHERE estado='Finalizado' AND
                    ((equipo_local_id=:a AND equipo_visitante_id=:b) OR (equipo_local_id=:b AND equipo_visitante_id=:a))
                    ORDER BY fecha_hora_juego""", a=a, b=b)
    return {"enfrentamientos": h, "victorias_a": sum(x["ganador_id"] == a for x in h),
            "victorias_b": sum(x["ganador_id"] == b for x in h)}


# ---------- Escritura (Árbitro / Admin) ----------
class Stat(BaseModel):
    id_jugador: int
    kills: int = Field(0, ge=0)
    puntos: int = Field(0, ge=0)
    faltas: int = Field(0, ge=0)
    minutos: int = Field(45, ge=0)


class Resultado(BaseModel):
    id_partido: int
    marcador_local: int = Field(ge=0)
    marcador_visitante: int = Field(ge=0)
    stats: list[Stat] = []


@app.post("/api/v1/partidos/resultado", tags=["partidos"])
def resultado(b: Resultado, user=Depends(require("arbitro", "admin"))):
    """Captura el marcador, guarda stats y propaga el ganador al siguiente cruce (una sola transacción)."""
    try:
        with engine.begin() as c:
            m = q(c, """SELECT p.*, (SELECT id_torneo FROM fases_rondas WHERE id_fase=p.id_fase) AS id_torneo
                        FROM partidos p WHERE p.id_partido=:i FOR UPDATE""", i=b.id_partido)
            if not m:
                raise HTTPException(404, "Partido no encontrado")
            m = m[0]
            if m["estado"] == "Finalizado":
                raise HTTPException(409, "Partido finalizado: marcador bloqueado")
            if not m["equipo_local_id"] or not m["equipo_visitante_id"]:
                raise HTTPException(409, "Faltan equipos: espera al ganador de la ronda previa")
            if b.marcador_local == b.marcador_visitante:
                raise HTTPException(422, "En eliminación directa no se permite empate")
            validos = {r["id_jugador"] for r in q(c, """
                SELECT r.id_jugador FROM roster_torneo r
                JOIN inscripciones_equipo i ON i.id_inscripcion = r.id_inscripcion
                WHERE i.id_torneo=:t AND i.id_equipo IN (:l,:v)""",
                t=m["id_torneo"], l=m["equipo_local_id"], v=m["equipo_visitante_id"])}
            for s in b.stats:
                if s.id_jugador not in validos:
                    raise HTTPException(422, f"El jugador {s.id_jugador} no está en el roster de este partido")
            g = m["equipo_local_id"] if b.marcador_local > b.marcador_visitante else m["equipo_visitante_id"]
            c.execute(text("""UPDATE partidos SET marcador_local=:a, marcador_visitante=:b,
                              ganador_id=:g, estado='Finalizado' WHERE id_partido=:i"""),
                      {"a": b.marcador_local, "b": b.marcador_visitante, "g": g, "i": b.id_partido})
            for s in b.stats:
                c.execute(text("""INSERT INTO estadisticas_partido (id_partido,id_jugador,puntos_anotados,
                    kills_o_asistencias,faltas_cometidas,minutos_jugados,confirmacion_arbitral)
                    VALUES (:p,:j,:pt,:k,:f,:mn,1)
                    ON DUPLICATE KEY UPDATE puntos_anotados=:pt, kills_o_asistencias=:k,
                      faltas_cometidas=:f, minutos_jugados=:mn, confirmacion_arbitral=1"""),
                          {"p": b.id_partido, "j": s.id_jugador, "pt": s.puntos, "k": s.kills,
                           "f": s.faltas, "mn": s.minutos})
            # Propagación en cascada del ganador (bracket)
            c.execute(text("UPDATE partidos SET equipo_local_id=:g WHERE partido_origen_local_id=:i"), {"g": g, "i": b.id_partido})
            c.execute(text("UPDATE partidos SET equipo_visitante_id=:g WHERE partido_origen_visita_id=:i"), {"g": g, "i": b.id_partido})
            # Si no alimenta a otro partido, era la final -> cierra el torneo
            if not q(c, "SELECT 1 FROM partidos WHERE partido_origen_local_id=:i OR partido_origen_visita_id=:i", i=b.id_partido):
                c.execute(text("UPDATE torneos SET estado='Finalizado', fecha_fin=CURRENT_DATE WHERE id_torneo=:t"), {"t": m["id_torneo"]})
    except DBAPIError as e:  # p. ej. SIGNAL 45000 del trigger de bloqueo
        raise HTTPException(409, str(e.orig))
    return {"ok": True, "ganador_id": g, "capturado_por": user["sub"]}


@app.post("/api/v1/partidos/{id_partido}/anular", tags=["partidos"])
def anular(id_partido: int, user=Depends(require("admin"))):
    """Solo Admin. Bloquea si la ronda siguiente ya finalizó (integridad del bracket)."""
    with engine.begin() as c:
        m = q(c, """SELECT p.*, (SELECT id_torneo FROM fases_rondas WHERE id_fase=p.id_fase) AS id_torneo
                    FROM partidos p WHERE id_partido=:i FOR UPDATE""", i=id_partido)
        if not m or m[0]["estado"] != "Finalizado":
            raise HTTPException(409, "Solo se pueden anular partidos finalizados")
        if q(c, """SELECT 1 FROM partidos WHERE estado='Finalizado'
                   AND (partido_origen_local_id=:i OR partido_origen_visita_id=:i)""", i=id_partido):
            raise HTTPException(409, "La ronda siguiente ya finalizó; anúlala primero")
        c.execute(text("""UPDATE partidos SET estado='Programado', ganador_id=NULL,
                          marcador_local=0, marcador_visitante=0 WHERE id_partido=:i"""), {"i": id_partido})
        c.execute(text("DELETE FROM estadisticas_partido WHERE id_partido=:i"), {"i": id_partido})
        c.execute(text("UPDATE partidos SET equipo_local_id=NULL WHERE partido_origen_local_id=:i"), {"i": id_partido})
        c.execute(text("UPDATE partidos SET equipo_visitante_id=NULL WHERE partido_origen_visita_id=:i"), {"i": id_partido})
        c.execute(text("UPDATE torneos SET estado='En Progreso', fecha_fin=NULL WHERE id_torneo=:t"), {"t": m[0]["id_torneo"]})
    return {"ok": True, "anulado_por": user["sub"]}


# ---------- Gestión de equipos (Admin) ----------

class EquipoIn(BaseModel):
    nombre_oficial: str = Field(..., min_length=1, max_length=100)
    tag: str = Field(..., min_length=1, max_length=10)
    logo_url: str | None = None


@app.get("/api/v1/equipos", tags=["equipos"])
def listar_equipos():
    """Lectura pública, igual que /torneos."""
    with engine.connect() as c:
        return q(c, "SELECT * FROM equipos ORDER BY nombre_oficial")


@app.post("/api/v1/equipos", tags=["equipos"], status_code=201)
def crear_equipo(e: EquipoIn, user=Depends(require("admin"))):
    with engine.begin() as c:
        if q(c, "SELECT 1 FROM equipos WHERE tag=:t", t=e.tag):
            raise HTTPException(409, f"Ya existe un equipo con el TAG '{e.tag}'")
        r = c.execute(text("""INSERT INTO equipos (nombre_oficial, tag, logo_url)
                             VALUES (:n, :t, :l)"""),
                      {"n": e.nombre_oficial, "t": e.tag, "l": e.logo_url})
    return {"ok": True, "id_equipo": r.lastrowid, "creado_por": user["sub"]}


@app.delete("/api/v1/equipos/{id_equipo}", tags=["equipos"])
def eliminar_equipo(id_equipo: int, user=Depends(require("admin"))):
    """Bloqueado por la base de datos (ON DELETE RESTRICT) si el equipo sigue
    inscrito en algún torneo. Hay que darlo de baja del torneo primero."""
    try:
        with engine.begin() as c:
            if not q(c, "SELECT 1 FROM equipos WHERE id_equipo=:i", i=id_equipo):
                raise HTTPException(404, "Equipo no encontrado")
            c.execute(text("DELETE FROM equipos WHERE id_equipo=:i"), {"i": id_equipo})
    except DBAPIError:
        raise HTTPException(409, "No se puede eliminar: el equipo sigue inscrito en uno o más "
                                  "torneos. Quítalo de las inscripciones antes de borrarlo.")
    return {"ok": True, "eliminado_por": user["sub"]}


# ---------- Reinicio de torneo (Admin) ----------

@app.post("/api/v1/torneos/{id_torneo}/reiniciar", tags=["torneos"])
def reiniciar_torneo(id_torneo: int, user=Depends(require("admin"))):
    """Regresa el torneo a su punto de partida para poder repetir la demo:
    borra marcadores y estadísticas, deja solo la ronda 1 con sus equipos
    originales, y limpia las rondas siguientes (que se llenan solas al jugar)."""
    with engine.begin() as c:
        if not q(c, "SELECT 1 FROM torneos WHERE id_torneo=:t", t=id_torneo):
            raise HTTPException(404, "Torneo no encontrado")

        c.execute(text("""DELETE s FROM estadisticas_partido s
                          JOIN partidos p ON p.id_partido = s.id_partido
                          JOIN fases_rondas f ON f.id_fase = p.id_fase
                          WHERE f.id_torneo=:t"""), {"t": id_torneo})

        c.execute(text("""UPDATE partidos p JOIN fases_rondas f ON f.id_fase = p.id_fase
                          SET p.marcador_local=0, p.marcador_visitante=0,
                              p.ganador_id=NULL, p.estado='Programado'
                          WHERE f.id_torneo=:t"""), {"t": id_torneo})

        # Solo se limpian los equipos de partidos que vienen de una ronda anterior;
        # la ronda 1 (sin partido_origen) conserva su emparejamiento original.
        c.execute(text("""UPDATE partidos p JOIN fases_rondas f ON f.id_fase = p.id_fase
                          SET p.equipo_local_id=NULL
                          WHERE f.id_torneo=:t AND p.partido_origen_local_id IS NOT NULL"""),
                  {"t": id_torneo})
        c.execute(text("""UPDATE partidos p JOIN fases_rondas f ON f.id_fase = p.id_fase
                          SET p.equipo_visitante_id=NULL
                          WHERE f.id_torneo=:t AND p.partido_origen_visita_id IS NOT NULL"""),
                  {"t": id_torneo})

        c.execute(text("UPDATE torneos SET estado='En Progreso', fecha_fin=NULL WHERE id_torneo=:t"),
                  {"t": id_torneo})
    return {"ok": True, "reiniciado_por": user["sub"]}
