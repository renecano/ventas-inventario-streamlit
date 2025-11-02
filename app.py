# -*- coding: utf-8 -*-
import contextlib, datetime as dt
import pandas as pd
import streamlit as st
import bcrypt
import os, time, hmac, hashlib, base64
from datetime import datetime, timedelta, timezone
import io, zipfile
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from sqlalchemy import create_engine, text
from urllib.parse import quote_plus
import time
import altair as alt
import psycopg2
import psycopg2.extras
import streamlit.components.v1 as components
from streamlit_cookies_manager import EncryptedCookieManager



st.set_page_config(page_title="Sistema de Ventas e Inventario", page_icon="📊", layout="wide")

st.markdown("""
<style>
:root{
  /* Colores del tema de Streamlit */
  --bg: var(--background-color);
  --bg2: var(--secondary-background-color);
  --txt: var(--text-color);
  --pri: var(--primary-color);
  --radius-xl:16px;
  --shadow-sm: 0 2px 8px rgba(0,0,0,.08);
  --shadow-md: 0 8px 24px rgba(0,0,0,.18);
  --border: color-mix(in oklab, var(--txt) 12%, transparent);
}

h1, h2, h3 { letter-spacing:-.01em; color: var(--txt); }
.block-container { padding-top:1.2rem; padding-bottom:2.0rem; max-width:1200px; }

/* Cards */
.card {
  background: var(--bg2);      /* antes: #fff */
  border: 1px solid var(--border);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-sm);
  padding: 1.1rem;
}
.card:hover { box-shadow: var(--shadow-md); }
/* Si una card no tiene contenido útil, no la muestres */
.card:empty { display:none; }
.card:has(.stAlert){ padding: .8rem; } /* alerta dentro = menos padding */

div.stButton > button, div.stDownloadButton > button { border-radius:12px; font-weight:600; }
.stTextInput input, .stNumberInput input, .stSelectbox div[data-baseweb="select"] { border-radius:12px !important; }
[data-testid="stMetricValue"] { font-size:1.4rem; }
.stDataFrame { border-radius:var(--radius-xl); overflow:hidden; }
[data-testid="stSidebar"] .block-container { padding-top:1rem; }
.sidebar-brand { display:flex; align-items:center; gap:.6rem; margin-bottom:.6rem; font-weight:700; font-size:1.05rem; color: var(--txt); }
.sidebar-badge { background: var(--bg2); color: var(--txt); padding:.25rem .5rem; border-radius:8px; font-size:.8rem; }

/* Tarjetas de mantenimiento */
.maint-box { display:flex; flex-wrap:wrap; gap:1rem; justify-content:center; margin-top:.5rem; }
.maint-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius:16px;
  box-shadow: var(--shadow-sm);
  padding:1.1rem; width:260px; text-align:center; transition:all .2s ease; color: var(--txt);
}
.maint-card:hover { box-shadow:0 6px 22px rgba(0,0,0,.25); transform: translateY(-3px); }
.maint-icon { font-size:36px; margin-bottom:10px; }
.maint-desc { color: color-mix(in oklab, var(--txt) 70%, transparent); font-size:.9rem; margin:.5rem 0 1rem; }

/* Quita “barras vacías” antes de inputs (espacios verticales grandes) */
section + div[data-testid="stVerticalBlock"] > div:empty { display:none; }
/* Quita bloques vacíos dentro de cualquier .card */
.card [data-testid="stVerticalBlock"] > div:empty { 
  display: none !important; 
}

/* Quita espaciadores vacíos dentro del grid de mantenimiento */
.maint-box > div[data-testid="stVerticalBlock"]:has(> div:empty) {
  display: none !important;
}

/* Evita márgenes/padding extra en wrappers del grid de mantenimiento */
.maint-box [data-testid="stVerticalBlock"] {
  margin: 0 !important;
  padding: 0 !important;
}

/* Evita que los <p> estiren la tarjeta */
.maint-card p { margin: 0; }

.vega-actions {
  display: none !important;
}

</style>
""", unsafe_allow_html=True)




# ---------- UI helpers ----------
def page_header(title: str, subtitle: str = "", icon: str = "📊"):
    st.markdown(f"""
    <div class="card" style="padding:1rem 1.2rem; margin-bottom:.75rem;">
      <div style="display:flex; align-items:center; gap:.75rem;">
        <div style="font-size:1.6rem">{icon}</div>
        <div>
          <div style="font-size:1.35rem; font-weight:800; line-height:1.2">{title}</div>
          <div style="color:#64748b; margin-top:.15rem">{subtitle}</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

def section(title: str, icon: str = "🧩"):
    st.markdown(f"""<h3 style="margin:.25rem 0 .35rem 0">{icon} {title}</h3>""", unsafe_allow_html=True)

def _sparkline(series_df, y, title, height=60):
    # series_df: DataFrame con columnas ['fecha', y]
    base = alt.Chart(series_df).mark_area(opacity=0.25).encode(
        x=alt.X('fecha:T', axis=None),
        y=alt.Y(f'{y}:Q', axis=None)
    ).properties(height=height)

    line = alt.Chart(series_df).mark_line().encode(
        x='fecha:T',
        y=f'{y}:Q',
        tooltip=[alt.Tooltip('fecha:T', title='Fecha', format='%d %b %Y'),
                 alt.Tooltip(f'{y}:Q', title=title, format=',.2f')]
    ).properties(height=height)

    return (base + line)

def viz_cards(items, cols=4):
    """
    items: lista de dicts con:
      - label (str)
      - value (str)
      - icon  (str)
      - series (pd.DataFrame con ['fecha', 'valor'])  -> se plotea como sparkline
      - title (str) título para tooltip/unidad
    """
    grid = st.columns(cols)
    for i, it in enumerate(items):
        with grid[i % cols]:
            st.markdown("""
            <div class="card" style="padding:.85rem 1rem">
              <div style="display:flex; gap:.6rem; align-items:center; margin-bottom:.35rem">
                <div style="font-size:1.35rem">{icon}</div>
                <div>
                  <div style="font-size:.8rem; color:#64748b">{label}</div>
                  <div style="font-size:1.2rem; font-weight:800">{value}</div>
                </div>
              </div>
            </div>
            """.format(icon=it.get('icon','🔹'), label=it['label'], value=it['value']), unsafe_allow_html=True)
            # Insertamos el sparkline justo debajo de la card para que quede visualmente "dentro"
            if it.get("series") is not None and not it["series"].empty:
                chart = _sparkline(it["series"], "valor", it.get("title",""))
                st.altair_chart(chart, use_container_width=True)



def period_controls(key_prefix: str = "", default_period: str = "Últimos 30 días"):
    """Devuelve (inicio, fin, freq, date_fmt) y pinta los controles.
    Usa key_prefix para evitar colisiones entre páginas (p. ej. 'panel', 'reportes')."""
    colp1, colp2 = st.columns([2, 2])

    period_options = [
        "Últimos 30 días",
        "Últimos 3 meses",
        "Últimos 6 meses",
        "Últimos 12 meses",
        "Año en curso",
        "Rango personalizado",
    ]
    periodo = colp1.selectbox(
        "Periodo",
        period_options,
        index=period_options.index(default_period),
        key=f"{key_prefix}_periodo",
    )
    resolucion = colp2.selectbox(
        "Resolución",
        ["Automático", "Por día", "Por semana", "Por mes"],
        index=0,
        key=f"{key_prefix}_resol",
    )

    hoy = pd.Timestamp.now(tz="UTC").normalize()
    if periodo == "Últimos 30 días":
        inicio = (hoy - pd.DateOffset(days=29)).date(); fin = hoy.date()
    elif periodo == "Últimos 3 meses":
        inicio = (hoy - pd.DateOffset(months=3)).date(); fin = hoy.date()
    elif periodo == "Últimos 6 meses":
        inicio = (hoy - pd.DateOffset(months=6)).date(); fin = hoy.date()
    elif periodo == "Últimos 12 meses":
        inicio = (hoy - pd.DateOffset(months=12)).date(); fin = hoy.date()
    elif periodo == "Año en curso":
        inicio = pd.Timestamp(hoy.year, 1, 1).date(); fin = hoy.date()
    else:
        c1d, c2d = st.columns(2)
        inicio = c1d.date_input("Desde", value=(hoy - pd.DateOffset(months=1)).date(), key=f"{key_prefix}_desde")
        fin    = c2d.date_input("Hasta",  value=hoy.date(), key=f"{key_prefix}_hasta")
        if inicio > fin:
            st.warning("La fecha 'Desde' no puede ser mayor que 'Hasta'.")
            st.stop()

    rango_dias = (pd.Timestamp(fin) - pd.Timestamp(inicio)).days
    if resolucion == "Automático":
        if   rango_dias <= 120:  freq = "D"
        elif rango_dias <= 400:  freq = "W"
        else:                    freq = "MS"
    elif resolucion == "Por día":
        freq = "D"
    elif resolucion == "Por semana":
        freq = "W"
    else:
        freq = "MS"

    date_fmt = "%d %b %Y" if freq in ("D", "W") else "%b %Y"
    return inicio, fin, freq, date_fmt


def stat_cards(items, cols=4):
    grid = st.columns(cols)
    for i, it in enumerate(items):
        with grid[i % cols]:
            st.markdown(f"""
            <div class="card" style="padding:.9rem 1rem">
              <div style="display:flex; gap:.6rem; align-items:center;">
                <div style="font-size:1.4rem">{it.get('icon','🔹')}</div>
                <div>
                  <div style="font-size:.85rem; color:#64748b">{it['label']}</div>
                  <div style="font-size:1.25rem; font-weight:800">{it['value']}</div>
                </div>
              </div>
            </div>
            """, unsafe_allow_html=True)

def ts_chart(serie: pd.DataFrame, date_fmt: str, key_prefix: str,
             x_col: str = "fecha", y_col: str = "Total ($ MXN)",
             y_title: str = "Ingresos (MXN)", y_fmt: str = "$,.2f"):
    """
    Pinta controles de visualización y dibuja una serie temporal con Altair.
    - serie: DataFrame con columnas [x_col, y_col]
    - date_fmt: formato para el eje X (p.ej. "%d %b %Y" ó "%b %Y")
    - key_prefix: para que los widgets no colisionen entre páginas
    - y_title / y_fmt: etiqueta y formato del eje Y
    """

    colv1, colv2 = st.columns([2, 2])
    tipo_graf = colv1.selectbox(
        "Visualización",
        ["Línea (recomendada)", "Barras", "Área suave"],
        index=0,
        key=f"{key_prefix}_viz"
    )
    mm_op = colv2.selectbox(
        "Media móvil",
        ["Sin media", "7 días", "30 días"],
        index=0,
        key=f"{key_prefix}_mm"
    )

    # Base
    base = alt.Chart(serie).properties(height=320)
    x_enc = alt.X(f"{x_col}:T", title="Fecha", axis=alt.Axis(format=date_fmt))
    y_enc = alt.Y(f"{y_col}:Q", axis=alt.Axis(format=y_fmt, title=y_title))

    line = base.mark_line().encode(x=x_enc, y=y_enc)
    pts  = base.mark_point().encode(x=x_enc, y=y_enc)
    bars = base.mark_bar().encode(x=x_enc, y=y_enc)
    area = base.mark_area().encode(x=x_enc, y=y_enc)

    tooltip = base.mark_rule(opacity=0).encode(
        x=x_enc, y=y_enc,
        tooltip=[alt.Tooltip(f"{x_col}:T", title="Fecha", format=date_fmt),
                 alt.Tooltip(f"{y_col}:Q", title=y_title, format=y_fmt)]
    )

    # Serie principal según tipo
    chart = {"Línea (recomendada)": (line + pts + tooltip),
             "Barras": (bars + tooltip),
             "Área suave": (area + line + tooltip)}[tipo_graf]

    # Media móvil opcional
    ventana = 7 if mm_op == "7 días" else (30 if mm_op == "30 días" else None)
    if ventana:
        serie_mm = serie.copy()
        serie_mm["__MM__"] = serie_mm[y_col].rolling(window=ventana, min_periods=1).mean()
        mm = alt.Chart(serie_mm).properties(height=320).mark_line(strokeDash=[6,4], color="#555").encode(
            x=x_enc,
            y=alt.Y("__MM__:Q", axis=alt.Axis(format=y_fmt)),
            tooltip=[alt.Tooltip("__MM__:Q", title=f"Media móvil ({ventana})", format=y_fmt)]
        )
        chart = chart + mm

    st.altair_chart(chart, use_container_width=True)



def set_flash(msg: str, kind: str = "info", ttl: float = 6.0):
    """
    Guarda un 'flash message' con tipo (success|error|warning|info) y tiempo de vida (segundos).
    """
    st.session_state["_flash"] = {
        "msg": msg,
        "kind": kind,
        "ts": time.time(),   # cuándo se creó
        "ttl": float(ttl),   # cuánto dura visible
    }

def show_flash():
    """
    Muestra el flash si existe. Permite cerrarlo con '×' y lo expira si ya pasó el TTL
    (en el siguiente rerender/interacción).
    """
    f = st.session_state.get("_flash")
    if not f:
        return

    # ¿ya venció?
    if time.time() - f["ts"] > f.get("ttl", 6.0):
        st.session_state.pop("_flash", None)
        return

    # Render con botón de cierre
    c1, c2 = st.columns([12, 1])
    render = {
        "success": c1.success,
        "error":   c1.error,
        "warning": c1.warning,
        "info":    c1.info,
    }.get(f.get("kind", "info"), c1.info)
    render(f["msg"])

    if c2.button("×", key=f"flash_close_{int(f['ts'])}", help="Ocultar mensaje"):
        st.session_state.pop("_flash", None)
        st.rerun()


class framed_block:
    def __enter__(self): st.markdown('<div class="card">', unsafe_allow_html=True)
    def __exit__(self, exc_type, exc, tb): st.markdown('</div>', unsafe_allow_html=True)




# ============================
# 1) Auth y seguridad
# ============================

REMEMBER_SECRET = (
    (getattr(st, "secrets", {}) or {}).get("REMEMBER_SECRET")
    or os.environ.get("REMEMBER_SECRET")
)
if not REMEMBER_SECRET:
    raise RuntimeError("⚠️ Falta REMEMBER_SECRET. Configúralo en .streamlit/secrets.toml o variable de entorno.")

REMEMBER_DAYS = 7
AUTH_COOKIE_NAME = "auth_token"
SKIP_COOKIE_ONCE_KEY = "_skip_cookie_once"

cookies = EncryptedCookieManager(
    prefix="myapp_",
    password=REMEMBER_SECRET
)

if not cookies.ready():
    st.stop()  # Espera a que las cookies carguen

CREDENTIALS = {
    "usernames": {
        "admin": {
            "name": "Administrador",
            "password": b"$2b$12$OsjHQXjKu4I8Ip3tQ9YygO1dYUwagxsB6Lg/jDIs/kCs3kiK7F86K",
            "role": "admin",
        },
        "caja1": {
            "name": "Cajero 1",
            "password": b"$2b$12$6nd8lt9.QsQS0SoH4HyGae2IAcvrwqZAJB7M3vecLm1grZPK1B6OK",
            "role": "cashier",
        },
    }
}

def _check_password(username: str, plain_password: str) -> bool:
    username = (username or "").strip().lower()
    if not username or not plain_password:
        time.sleep(0.2)
        return False
    try:
        users = CREDENTIALS.get("usernames", {})
        urec = users.get(username)
        if not urec:
            time.sleep(0.2)
            return False
        stored_hash = urec["password"]
        ok = bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash)
        return bool(ok)
    except Exception:
        time.sleep(0.2)
        return False

def _sign(msg: str) -> str:
    sig = hmac.new(REMEMBER_SECRET.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode("ascii")

def _create_token(username: str, days_valid: int) -> str:
    username = (username or "").strip().lower()
    exp_ts = int(time.time()) + days_valid * 86400
    urec = CREDENTIALS["usernames"][username]
    hfp = base64.urlsafe_b64encode(urec["password"][:16]).decode("ascii")
    u_b64 = base64.urlsafe_b64encode(username.encode("utf-8")).decode("ascii")
    payload = f"{u_b64}|{exp_ts}|{hfp}"
    sig = _sign(payload)
    return f"{payload}|{sig}"

def _verify_token(token: str) -> bool:
    try:
        parts = token.split("|")
        if len(parts) != 4:
            return False
        u_b64, exp_ts, hfp, sig = parts
        payload = f"{u_b64}|{exp_ts}|{hfp}"
        if not hmac.compare_digest(sig, _sign(payload)):
            return False
        if time.time() > int(exp_ts):
            return False
        username = base64.urlsafe_b64decode(u_b64.encode("ascii")).decode("utf-8")
        urec = CREDENTIALS.get("usernames", {}).get(username)
        if not urec:
            return False
        cur_hfp = base64.urlsafe_b64encode(urec["password"][:16]).decode("ascii")
        return hfp == cur_hfp
    except Exception:
        return False


def _username_from_token(token: str) -> str | None:
    try:
        u_b64 = token.split("|", 1)[0]
        return base64.urlsafe_b64decode(u_b64.encode("ascii")).decode("utf-8")
    except Exception:
        return None

def _do_login(username: str):
    username = (username or "").strip().lower()
    urec = CREDENTIALS["usernames"].get(username)
    if not urec:
        return
    st.session_state["user"] = {
        "username": username,
        "name": urec["name"],
        "role": urec.get("role", "cashier"),
        "logged": True,
    }

def _do_logout():
    """Cierra sesión de forma limpia"""
    # Borra cookie
    if AUTH_COOKIE_NAME in cookies:
        del cookies[AUTH_COOKIE_NAME]
    cookies.save()
    
    st.session_state.clear()
    st.rerun()

def login_ui():
    """Pantalla de login"""
    page_header("Iniciar sesión", "Acceso al sistema", icon="🔐")

    with framed_block():
        with st.form("login_form", clear_on_submit=False):
            u = st.text_input("Usuario", placeholder="usuario")
            p = st.text_input("Contraseña", type="password")
            remember = st.checkbox("Recordarme en este equipo (7 días)", value=True)
            submitted = st.form_submit_button("Entrar")

    if submitted:
        u_n = (u or "").strip().lower()
        
        if _check_password(u_n, p):
            _do_login(u_n)

            if remember:
                token = _create_token(u_n, REMEMBER_DAYS)
                cookies[AUTH_COOKIE_NAME] = token
                cookies.save()
            else:
                if AUTH_COOKIE_NAME in cookies:
                    del cookies[AUTH_COOKIE_NAME]
                cookies.save()

            st.rerun()
        else:
            st.session_state.pop("user", None)
            if AUTH_COOKIE_NAME in cookies:
                del cookies[AUTH_COOKIE_NAME]
            cookies.save()
            st.error("❌ Usuario o contraseña incorrectos.")



if "user" not in st.session_state or not st.session_state.get("user", {}).get("logged"):
    skip_cookie = st.session_state.pop(SKIP_COOKIE_ONCE_KEY, False)
    
    if not skip_cookie and not st.session_state.get("_autologin_attempted"):
        st.session_state["_autologin_attempted"] = True
        
        # Leer cookie encriptada
        token = cookies.get(AUTH_COOKIE_NAME)
        
        if token and _verify_token(token):
            u_tok = _username_from_token(token)
            if u_tok and u_tok in CREDENTIALS.get("usernames", {}):
                _do_login(u_tok)
                st.rerun()

# Verificación de sesión
user_session = st.session_state.get("user", {})
is_logged = user_session.get("logged") == True

if not is_logged:
    login_ui()
    st.stop()

st.session_state.pop("_login_success", None)

# Verificación de sesión
user_session = st.session_state.get("user", {})
is_logged = user_session.get("logged") == True

if not is_logged:
    login_ui()
    st.stop()

# Si acabamos de hacer login exitoso, limpiamos el flag
st.session_state.pop("_login_success", None)


# Versor para invalidar caché de configuración
if "cfg_ver" not in st.session_state:
    st.session_state["cfg_ver"] = 0



# Sidebar con branding y botón de cierre de sesión
with st.sidebar:
    st.markdown(
        '<div class="sidebar-brand">🧾 <span>Mi Negocio</span> '
        '<span class="sidebar-badge">POS</span></div>',
        unsafe_allow_html=True
    )
    st.write(f"👤 {st.session_state['user']['name']} · Rol: **{st.session_state['user']['role']}**")

    # 🔒 Botón completo para cerrar sesión y borrar cookies correctamente
    if st.button("Cerrar sesión", use_container_width=True):
        _do_logout()


def require_admin():
    u = st.session_state.get("user") or {}
    role = u.get("role")
    logged = bool(u.get("logged"))
    if not logged or role != "admin":
        # paranoia: asegúrate de no dejar residuos de sesión
        st.session_state.pop("user", None)
        st.error("No autorizado. Solo administradores.")
        st.stop()




# ============================
# 2) DB y helpers (PostgreSQL)
# ============================



try:
    PG = st.secrets["postgres"]
except KeyError:
    st.error("⚠️ Falta configuración de PostgreSQL en secrets.toml")
    st.code("""
    # .streamlit/secrets.toml
    [postgres]
    host = "tu-host.aws.com"
    port = 5432
    dbname = "tu_db"
    user = "tu_usuario"
    password = "tu_password"
    sslmode = "require"
    """)
    st.stop()

def _conn_kwargs():
    return dict(
        host=PG["host"],
        port=int(PG.get("port", 5432)),
        dbname=PG["dbname"],
        user=PG["user"],
        password=PG["password"],
        sslmode=PG.get("sslmode", "prefer"),
    )

@st.cache_resource
def _sa_engine():
    url = (
        "postgresql+psycopg2://"
        f"{quote_plus(PG['user'])}:{quote_plus(PG['password'])}"
        f"@{PG['host']}:{int(PG.get('port', 5432))}/{PG['dbname']}"
        f"?sslmode={PG.get('sslmode', 'prefer')}"
    )
    return create_engine(url, pool_pre_ping=True)



@contextlib.contextmanager
def get_conn():
    """
    Context manager que abre una conexión a PostgreSQL y hace commit/rollback automático.
    Sustituye al get_conn() de SQLite.
    """
    conn = psycopg2.connect(**_conn_kwargs())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def _q(sql: str) -> str:
    """
    Convierte los placeholders estilo SQLite (?) a estilo psycopg2 (%s).
    Tus consultas actuales usan '?', así evitamos tocarlas una por una.
    """
    return sql.replace('?', '%s')

def _q_sa(sql: str) -> str:
    """Convierte los ? en :p1, :p2, etc., para SQLAlchemy."""
    out, i = [], 1
    for ch in sql:
        if ch == "?":
            out.append(f":p{i}")
            i += 1
        else:
            out.append(ch)
    return "".join(out)

def _sa_params(params):
    """Convierte lista o tupla de parámetros a dict {p1: val1, p2: val2}"""
    if isinstance(params, (list, tuple)):
        return {f"p{i+1}": params[i] for i in range(len(params))}
    return params or {}


def df_read(query, params=()):
    eng = _sa_engine()
    with eng.connect() as conn:
        return pd.read_sql_query(text(_q_sa(query)), conn, params=_sa_params(params))



def exec_sql(query, params=()):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(_q(query), params)

def exec_many(query, params_list):
    with get_conn() as conn:
        with conn.cursor() as cur:
            psycopg2.extras.execute_batch(cur, _q(query), params_list, page_size=100)

@st.cache_data(ttl=600, show_spinner=False)
def _load_settings_cached(_version: int) -> dict:
    dfset = df_read('SELECT key, value FROM settings')
    kv = {r["key"]: r["value"] for _, r in dfset.iterrows()} if not dfset.empty else {}

    def _to_bool(s, default=False):
        if s is None: return default
        return str(s).strip().lower() in ("1","true","yes","si","sí","on")

    return {
        "iva_rate": float(kv.get("iva_rate", "0.16") or 0.16),
        "prices_include_iva": _to_bool(kv.get("prices_include_iva", "true"), default=True),
        "currency": kv.get("currency", "$ MXN"),
        "business_name": kv.get("business_name", "Mi Negocio"),
        "cost_method": kv.get("cost_method", "ultimo"),
        "show_db_diag": _to_bool(kv.get("show_db_diag", "false"), default=False), 
        "kiosk_mode": _to_bool(kv.get("kiosk_mode", "false"), default=False),
    }


def get_settings() -> dict:
    ver = st.session_state.get("cfg_ver", 0)
    return _load_settings_cached(ver)

def set_setting(key: str, value: str):
    exec_sql("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (key, value))
    st.session_state["cfg_ver"] = st.session_state.get("cfg_ver", 0) + 1
    _load_settings_cached.clear()

# ---------- Ajustes de init/migrate ----------
def init_db():
    """
    Ya creaste las tablas en PostgreSQL con pgAdmin.
    Aquí NO hacemos nada (antes creábamos tablas/PRAGMA en SQLite).
    """
    return True

def migrate_db():
    """Sin operaciones de migración para PostgreSQL por ahora."""
    return




# ============================
# 3) Operaciones de dominio
# ============================

def add_product(name, price, cost=0.0, stock=0.0, min_stock=0.0, sku=None, category=None):
    exec_sql("""INSERT INTO products (name, sku, price, cost, stock, min_stock, category)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
             (name, sku, price, cost, stock, min_stock, category))

def update_product(product_id, name, sku, price, cost, stock, min_stock, category):
    try:
        exec_sql("""
            UPDATE products
            SET name = ?, sku = ?, price = ?, cost = ?, stock = ?, min_stock = ?, category = ?
            WHERE id = ?
        """, (name, sku, float(price), float(cost), float(stock), float(min_stock), category, int(product_id)))
        return True
    except Exception as e:
        return {"ok": False, "error": str(e)}

def update_stock(product_id, delta):
    try:
        exec_sql("UPDATE products SET stock = stock + ? WHERE id = ?", (delta, product_id))
        return True
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _utc_now():
    return dt.datetime.now(dt.timezone.utc)

def record_sale(items, payment_method="Efectivo", note=""):
    if not items:
        return {"ok": False, "error": "No hay productos en la venta."}

    cfg = get_settings()
    iva_rate = float(cfg["iva_rate"])
    prices_include_iva = bool(cfg["prices_include_iva"])

    # ── 1) Reunir IDs de producto desde items (acepta product_id o id)
    ids = []
    for it in items:
        pid = it.get("product_id") or it.get("id")
        if pid is not None:
            try:
                ids.append(int(pid))
            except ValueError:
                pass
    ids = sorted(set(ids))
    if not ids:
        return {"ok": False, "error": "No hay productos válidos en la venta."}

    # ── 2) Leer precios/costos/stock usando placeholders nombrados (:id0, :id1, ...)
    ph = ",".join([f":id{i}" for i in range(len(ids))])
    params = {f"id{i}": v for i, v in enumerate(ids)}

    dfp = df_read(
        f"SELECT id, price, cost, stock FROM products WHERE id IN ({ph})",
        params
    )
    if dfp.empty:
        return {"ok": False, "error": "Productos no encontrados."}

    info = {
        int(r["id"]): {
            "price": float(r["price"]),
            "cost":  float(r["cost"]),
            "stock": float(r["stock"]),
        }
        for _, r in dfp.iterrows()
    }

    # ── 3) Validar stock
    faltantes = []
    for it in items:
        pid = int(it.get("product_id") or it.get("id"))
        qty = float(it["qty"])
        if pid not in info:
            faltantes.append(f"ID {pid}: no existe en catálogo")
        elif qty > info[pid]["stock"]:
            faltantes.append(f"ID {pid}: pides {qty:.0f}, hay {info[pid]['stock']:.0f}")
    if faltantes:
        return {"ok": False, "error": "Stock insuficiente → " + ", ".join(faltantes)}

    # ── 4) Calcular totales y renglones
    subtotal = 0.0
    total = 0.0
    sale_items_rows = []  # (pid, qty, net_unit, cost)

    for it in items:
        pid = int(it.get("product_id") or it.get("id"))
        qty = float(it["qty"])
        base_price = info[pid]["price"]
        cost       = info[pid]["cost"]

        if prices_include_iva:
            net_unit   = base_price / (1.0 + iva_rate)
            gross_unit = base_price
        else:
            net_unit   = base_price
            gross_unit = base_price * (1.0 + iva_rate)

        subtotal += net_unit * qty
        total    += gross_unit * qty
        sale_items_rows.append((pid, qty, net_unit, cost))

    iva = total - subtotal
    now = _utc_now()  # 'YYYY-MM-DD HH:MM:SS'

    # ── 5) Persistir en BD (psycopg2 usa %s, aquí sí aplica)
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # Cabecera
                cur.execute(
                    'INSERT INTO sales ("date", subtotal, iva, total, payment_method, note) '
                    'VALUES (%s, %s, %s, %s, %s, %s) RETURNING id',
                    (now, float(subtotal), float(iva), float(total), payment_method, note)
                )
                sale_id = cur.fetchone()[0]

                # Detalle (batch)
                psycopg2.extras.execute_batch(
                    cur,
                    'INSERT INTO sale_items (sale_id, product_id, qty, price, cost) '
                    'VALUES (%s, %s, %s, %s, %s)',
                    [(sale_id, int(pid), float(qty), float(net), float(cost))
                     for (pid, qty, net, cost) in sale_items_rows],
                    page_size=100
                )

                # Descontar inventario (batch)
                psycopg2.extras.execute_batch(
                    cur,
                    'UPDATE products SET stock = stock - %s WHERE id = %s',
                    [(float(qty), int(pid)) for (pid, qty, _, _) in sale_items_rows],
                    page_size=100
                )

        return {
            "ok": True,
            "sale_id": sale_id,
            "subtotal": round(subtotal, 2),
            "iva": round(iva, 2),
            "total": round(total, 2),
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}



def record_purchase(items, supplier=None, note="", create_expense=False, update_cost=True):
    if not items:
        return {"ok": False, "error": "No hay productos en la compra."}

    cfg = get_settings()
    method = cfg.get("cost_method", "ultimo")
    now = _utc_now()
    total = sum(float(it["qty"]) * float(it["cost"]) for it in items)

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1) Cabecera (ojo: "date" entre comillas)
                cur.execute(
                    'INSERT INTO purchases ("date", total, supplier, note) VALUES (%s, %s, %s, %s) RETURNING id',
                    (now, float(total), supplier, note)
                )
                purchase_id = cur.fetchone()[0]

                # Normalizamos/validamos renglones
                rows = []
                for it in items:
                    pid = int(it["product_id"])
                    qty = float(it["qty"])
                    cost = float(it["cost"])
                    if qty <= 0 or cost < 0:
                        raise ValueError("Cantidad > 0 y costo ≥ 0.")
                    rows.append((purchase_id, pid, qty, cost))

                # 2) Detalle (batch)
                psycopg2.extras.execute_batch(
                    cur,
                    'INSERT INTO purchase_items (purchase_id, product_id, qty, cost) VALUES (%s, %s, %s, %s)',
                    rows, page_size=100
                )

                # 3) Actualizar stock (batch)
                psycopg2.extras.execute_batch(
                    cur,
                    'UPDATE products SET stock = stock + %s WHERE id = %s',
                    [(qty, pid) for (_, pid, qty, _) in rows],
                    page_size=100
                )

                # 4) Actualizar costo del producto (opcional)
                if update_cost:
                    if method == "ultimo":
                        psycopg2.extras.execute_batch(
                            cur,
                            'UPDATE products SET cost = %s WHERE id = %s',
                            [(cost, pid) for (_, pid, _, cost) in rows],
                            page_size=100
                        )
                    else:
                        # promedio ponderado
                        for (_, pid, qty, cost) in rows:
                            cur.execute('SELECT stock, cost FROM products WHERE id = %s', (pid,))
                            s, c = cur.fetchone()
                            s = float(s or 0.0); c = float(c or 0.0)
                            prev_stock = max(s - qty, 0.0)  # stock antes de sumar esta compra
                            new_stock  = prev_stock + qty
                            prev_val   = prev_stock * c
                            add_val    = qty * cost
                            new_cost   = 0.0 if new_stock <= 1e-12 else (prev_val + add_val) / new_stock
                            cur.execute('UPDATE products SET cost = %s WHERE id = %s', (new_cost, pid))

                # 5) Registrar gasto (opcional)
                if create_expense and total > 0:
                    cur.execute(
                        'INSERT INTO expenses ("date", category, amount, note) VALUES (%s, %s, %s, %s)',
                        (now, "Compras", float(total), f"Compra a {supplier or "Proveedor"}")
                    )

        return True

    except Exception as e:
        return {"ok": False, "error": str(e)}


def record_expense(category, amount, note=""):
    now = _utc_now()
    exec_sql("INSERT INTO expenses (date, category, amount, note) VALUES (?, ?, ?, ?)",
             (now, category, float(amount), note))

# ============================
# 4) Utilidades UI
# ============================

def style_inventory(df, stock_col="Existencias", min_col="Nivel mínimo de existencia"):
    df_disp = df.copy()

    def _format_val(stock, minimo):
        try:
            stock = float(stock or 0)
            minimo = float(minimo or 0)
        except ValueError:
            return str(stock)
        icon = "⚠️" if stock <= minimo * 1.2 else ""
        return f"{(icon + ' ') if icon else ''}{stock:.2f}"

    df_disp[stock_col] = [
        _format_val(row[stock_col], row[min_col]) for _, row in df_disp.iterrows()
    ]

    def _row_style(row):
        try:
            stock = float(str(row[stock_col]).replace("⚠️", "").strip())
            minimo = float(row[min_col])
        except Exception:
            return [""] * len(row)

        if stock <= minimo:
            color = "#ffe2e2"  # rojo suave
        elif stock <= minimo * 1.2:
            color = "#fff5d9"  # amarillo claro
        else:
            color = "#f6fff1"  # verde muy claro
        return [f"background-color:{color};"] * len(row)

    styled = df_disp.style.apply(_row_style, axis=1)
    return styled


def fmt_date_clean(x):
    """
    Devuelve fechas limpias tipo: 28 Oct 2025 18:32
    (sin microsegundos ni zonas horarias).
    """
    try:
        # Parse universal y quita tz si la hay
        ts = pd.to_datetime(x, utc=True, errors="coerce")
        if pd.isna(ts):
            # Si no se pudo parsear como fecha, regresa texto tal cual
            return str(x)
        return ts.tz_convert(None).strftime("%d %b %Y %H:%M")
    except Exception:
        try:
            return pd.to_datetime(x).strftime("%d %b %Y %H:%M")
        except Exception:
            return str(x)


# ---------- Utils: exportaciones CSV ----------
def _date_range_filename(prefix: str, inicio: pd.Timestamp | dt.date, fin: pd.Timestamp | dt.date) -> str:
    ini = pd.to_datetime(inicio).strftime("%Y%m%d")
    fn  = pd.to_datetime(fin).strftime("%Y%m%d")
    return f"{prefix}_{ini}_a_{fn}.csv"

def csv_download(df: pd.DataFrame, filename: str, label: str = "⬇️ Descargar CSV", preview=True):
    # CSV crudo (sin alterar fechas)
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    st.download_button(label, data=csv_bytes, file_name=filename, mime="text/csv", key=f"dl_{filename}_{hash(filename)}", width='stretch')

    # Vista opcional con fechas limpias
    if preview:
        df_view = df.copy()
        for col in df_view.columns:
            if "fecha" in col.lower():  # o lista explícita ['Fecha', 'fecha', ...]
                df_view[col] = df_view[col].map(fmt_date_clean)
        st.dataframe(df_view, width='stretch')


def build_sales_export(inicio: dt.date, fin: dt.date) -> pd.DataFrame:
    cfg = get_settings()
    iva_rate = float(cfg["iva_rate"])
    df = df_read("""
        SELECT
            s.id               AS "ID",
            s."date"           AS "Fecha",
            s.payment_method   AS "Pago",
            p.name             AS "Producto",
            si.qty             AS "Cantidad",
            si.price           AS "PrecioNeto"
        FROM sales s
        JOIN sale_items si ON si.sale_id = s.id
        JOIN products p    ON p.id = si.product_id
        WHERE s."date"::date BETWEEN ? AND ?
        ORDER BY s."date" DESC, s.id DESC
    """, (pd.to_datetime(inicio).date().isoformat(), pd.to_datetime(fin).date().isoformat()))

    if df.empty:
        return df

    df["PrecioConIVA"] = df["PrecioNeto"] * (1.0 + iva_rate)
    df["ImporteNeto"]  = df["Cantidad"] * df["PrecioNeto"]
    df["ImporteIVA"]   = df["Cantidad"] * df["PrecioNeto"] * iva_rate
    df["ImporteTotal"] = df["Cantidad"] * df["PrecioConIVA"]

    cols = [
        "ID", "Fecha", "Pago", "Producto", "Cantidad",
        "PrecioNeto", "PrecioConIVA", "ImporteNeto", "ImporteIVA", "ImporteTotal"
    ]
    return df[cols]


def build_purchases_export(inicio, fin):
    df = df_read("""
        SELECT
            p.id         AS "ID",
            p."date"     AS "Fecha",
            p.supplier   AS "Proveedor",
            p.total      AS "Total",
            pr.name      AS "Producto",
            pi.qty       AS "Cantidad",
            pi.cost      AS "CostoUnit"
        FROM purchases p
        JOIN purchase_items pi ON pi.purchase_id = p.id
        JOIN products pr       ON pr.id = pi.product_id
        WHERE p."date"::date BETWEEN ? AND ?
        ORDER BY p."date" DESC
    """, (inicio.isoformat(), fin.isoformat()))

    if df.empty:
        return df

    df["ImporteLinea"] = df["Cantidad"] * df["CostoUnit"]
    cols = ["ID","Fecha","Proveedor","Total","Producto","Cantidad","CostoUnit","ImporteLinea"]
    return df[cols]




# ============================
# 5) Tickets (HTML)
# ============================

def build_receipt_html(sale_id: int, conn=None):
    # Consultas base
    qh = """SELECT id, "date", subtotal, iva, total, payment_method, note
            FROM sales WHERE id=?"""
    qd = """SELECT p.name, si.qty, si.price, si.cost
            FROM sale_items si 
            JOIN products p ON p.id = si.product_id
            WHERE si.sale_id=?"""

    # --- Encabezado ---
    head_df = df_read(qh, (sale_id,))
    if head_df.empty:
        return "<html><body><p>Venta no encontrada</p></body></html>"
    head = head_df.iloc[0]

    # --- Detalle ---
    detail = df_read(qd, (sale_id,))

    # --- Construcción del HTML ---
    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            h2 {{ text-align: center; }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                border-bottom: 1px solid #ccc;
                text-align: left;
                padding: 4px;
            }}
            tfoot td {{
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <h2>Ticket de venta #{int(head['id'])}</h2>
        <p><b>Fecha:</b> {head['date']}<br>
           <b>Método de pago:</b> {head.get('payment_method', '')}<br>
           <b>Nota:</b> {head.get('note') or ''}</p>

        <table>
            <thead>
                <tr>
                    <th>Producto</th>
                    <th>Cantidad</th>
                    <th>Precio</th>
                    <th>Importe</th>
                </tr>
            </thead>
            <tbody>
    """

    for _, r in detail.iterrows():
        importe = float(r.qty) * float(r.price)
        html += f"""
        <tr>
            <td>{r.name}</td>
            <td>{r.qty}</td>
            <td>${float(r.price):.2f}</td>
            <td>${importe:.2f}</td>
        </tr>
        """

    html += f"""
            </tbody>
            <tfoot>
                <tr><td colspan="3">Subtotal</td><td>${float(head['subtotal']):.2f}</td></tr>
                <tr><td colspan="3">IVA</td><td>${float(head['iva']):.2f}</td></tr>
                <tr><td colspan="3">Total</td><td>${float(head['total']):.2f}</td></tr>
            </tfoot>
        </table>
    </body>
    </html>
    """

    return html


def build_receipt_pdf(sale_id: int) -> bytes:
    # Consultas (ojo con "date" entre comillas)
    qh = '''SELECT id, "date" AS date, subtotal, iva, total, payment_method, note
            FROM sales WHERE id=?'''
    qd = '''SELECT p.name, si.qty, si.price, si.cost
            FROM sale_items si 
            JOIN products p ON p.id = si.product_id
            WHERE si.sale_id=?'''

    # Lee encabezado y detalle con SQLAlchemy (df_read hace el mapeo ? -> :p1)
    head_df = df_read(qh, (sale_id,))
    if head_df.empty:
        raise ValueError("Venta no encontrada")
    head = head_df.iloc[0]

    detail = df_read(qd, (sale_id,))

    # --- Configuración general de layout ---
    cfg       = get_settings()
    mon       = cfg["currency"]            # p.ej. "$ MXN"
    mon_sym   = "$" if "$" in mon else (mon.split()[0] if mon else "$")  # símbolo corto para renglones
    negocio   = cfg["business_name"]
    iva_rate  = float(cfg["iva_rate"])
    fecha_txt = pd.to_datetime(head["date"]).strftime("%d %b %Y %H:%M")

    # Ticket 80mm
    WIDTH  = 80 * mm
    HEIGHT = 210 * mm          # un poco más alto por si hay 2 líneas de nombre
    MARGIN = 5 * mm

    buf = io.BytesIO()
    cpdf = canvas.Canvas(buf, pagesize=(WIDTH, HEIGHT))

    # Helpers
    def new_page():
        cpdf.showPage()
        cpdf.setFont("Helvetica", 10)
        return HEIGHT - MARGIN

    def draw_text(x, y, text, size=10, bold=False):
        cpdf.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        cpdf.drawString(x, y, text)

    def draw_right(x_right, y, text, size=10, bold=False):
        font = "Helvetica-Bold" if bold else "Helvetica"
        cpdf.setFont(font, size)
        w = cpdf.stringWidth(text, font, size)
        cpdf.drawString(x_right - w, y, text)

    def wrap_text(text, max_width, size=10):
        """Rompe por palabras para que quepa en max_width."""
        words = str(text).split()
        lines, cur = [], ""
        while words:
            nxt = (cur + " " + words[0]).strip()
            w = cpdf.stringWidth(nxt, "Helvetica", size)
            if w <= max_width:
                cur = nxt
                words.pop(0)
            else:
                lines.append(cur or words.pop(0))
                cur = ""
            if len(lines) == 2 and words:   # limita a 2 líneas; lo que sobre se recorta con "…"
                leftover = " ".join(words)
                while cpdf.stringWidth(cur + " …", "Helvetica", size) > max_width and cur:
                    cur = cur[:-1]
                lines.append((cur + " …").strip() if cur else "…")
                return lines
        if cur:
            lines.append(cur)
        return lines

    # Encabezado
    y = HEIGHT - MARGIN
    cpdf.setFont("Helvetica", 10)
    draw_text(MARGIN, y, negocio, size=12, bold=True); y -= 14
    draw_text(MARGIN, y, f"Folio: #{int(head['id'])}"); y -= 12
    draw_text(MARGIN, y, f"Fecha: {fecha_txt}"); y -= 12
    draw_text(MARGIN, y, f"Pago: {head['payment_method'] or '-'}"); y -= 12

    # Separador
    cpdf.line(MARGIN, y, WIDTH - MARGIN, y); y -= 9

    # Definir columnas (en mm convertidos a puntos ya están)
    # ---------------- Columnas con anchos dinámicos ----------------
    # Texto “máximo” esperado para cada columna (ajústalos si vendes importes mayores)
    ROW_FONT = 10
    PAD = 8   # acolchonado mínimo entre columnas

    sample_qty    = "9999"                # 4 cifras de cantidad
    sample_price  = f"{mon_sym} 9999.99"  # precio unitario
    sample_import = f"{mon_sym} 99999.99" # importe por línea (más largo)

    w_qty    = cpdf.stringWidth(sample_qty,   "Helvetica", ROW_FONT)
    w_price  = cpdf.stringWidth(sample_price, "Helvetica", ROW_FONT)
    w_import = cpdf.stringWidth(sample_import,"Helvetica", ROW_FONT)

    COL_IMP_RIGHT   = WIDTH - MARGIN
    COL_PRICE_RIGHT = COL_IMP_RIGHT - (w_import + PAD)
    COL_QTY_RIGHT   = COL_PRICE_RIGHT - (w_price  + PAD)
    COL_NAME_LEFT   = MARGIN
    NAME_BOX_WIDTH  = COL_QTY_RIGHT - COL_NAME_LEFT - PAD

    # Encabezados
    y_headers = y
    draw_text(COL_NAME_LEFT,   y_headers, "Prod",    size=ROW_FONT)
    draw_right(COL_QTY_RIGHT,  y_headers, "Cant",    size=ROW_FONT)
    draw_right(COL_PRICE_RIGHT,y_headers, "P.Neto",  size=ROW_FONT)
    draw_right(COL_IMP_RIGHT,  y_headers, "Importe", size=ROW_FONT)
    y -= 12

    # ---------------- Filas ----------------
    ROW_LEAD = 12

    def draw_row(name, qty, pnet, imp, yrow):
        # Nombre envuelto a 1–2 líneas
        lines = wrap_text(name, NAME_BOX_WIDTH, size=ROW_FONT)
        for i, ln in enumerate(lines[:2]):
            draw_text(COL_NAME_LEFT, yrow - i*ROW_LEAD, ln, size=ROW_FONT)

        # Números alineados a la derecha (símbolo corto para ahorrar espacio)
        draw_right(COL_QTY_RIGHT,   yrow, f"{qty:.0f}",            size=ROW_FONT)
        draw_right(COL_PRICE_RIGHT, yrow, f"{mon_sym} {pnet:.2f}", size=ROW_FONT)
        draw_right(COL_IMP_RIGHT,   yrow, f"{mon_sym} {imp:.2f}",  size=ROW_FONT)

        return yrow - ROW_LEAD * max(1, len(lines[:2]))

    for _, r in detail.iterrows():
        name = str(r["name"])
        qty  = float(r["qty"])
        pnet = float(r["price"])
        imp  = qty * pnet * (1.0 + iva_rate)

        # Salto de página con reencabezado
        if y < 36:
            y = new_page()
            draw_text(COL_NAME_LEFT,   y, "Prod",    size=ROW_FONT)
            draw_right(COL_QTY_RIGHT,  y, "Cant",    size=ROW_FONT)
            draw_right(COL_PRICE_RIGHT,y, "P.Neto",  size=ROW_FONT)
            draw_right(COL_IMP_RIGHT,  y, "Importe", size=ROW_FONT)
            y -= 12

        y = draw_row(name, qty, pnet, imp, y)


    # -------- Totales (alineación dinámica) --------
    if y < 44:
        y = new_page()
    cpdf.line(MARGIN, y, WIDTH - MARGIN, y); y -= 10

    subtotal = float(head["subtotal"])
    iva      = float(head["iva"])
    total    = float(head["total"])

    # fuente y padding
    TOT_FONT = 10
    PAD = 8

    # medimos el ancho MÁXIMO de los importes (con moneda completa)
    txt_sub = f"{mon} {subtotal:.2f}"
    txt_iva = f"{mon} {iva:.2f}"
    txt_tot = f"{mon} {total:.2f}"
    w_amount_max = max(
        cpdf.stringWidth(txt_sub, "Helvetica", TOT_FONT),
        cpdf.stringWidth(txt_iva,  "Helvetica", TOT_FONT),
        cpdf.stringWidth(txt_tot,  "Helvetica", TOT_FONT),
    )

    AMOUNT_RIGHT = WIDTH - MARGIN                         # borde derecho
    LABEL_RIGHT  = AMOUNT_RIGHT - w_amount_max - PAD      # ancla para las etiquetas

    # dibujamos cada línea
    def draw_total_line(label, value, yrow):
        draw_right(LABEL_RIGHT,  yrow, label,            size=TOT_FONT)    # etiqueta pegada al importe
        draw_right(AMOUNT_RIGHT, yrow, f"{mon} {value:.2f}", size=TOT_FONT) # importe a la derecha
        return yrow - 12

    y = draw_total_line("Subtotal:", subtotal, y)
    y = draw_total_line("IVA:",      iva,      y)
    y = draw_total_line("Total:",    total,    y - 4)  # pequeño extra de espacio antes de Total
    draw_text(MARGIN, y, "¡Gracias por su compra!")



    cpdf.save()
    pdf_bytes = buf.getvalue()
    buf.close()
    return pdf_bytes



def create_backup_zip() -> io.BytesIO:
    tablas = ["products", "sales", "sale_items", "purchases", "purchase_items", "expenses", "settings"]
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as z:
        for t in tablas:
            try:
                df = df_read(f'SELECT * FROM {t}')
                csv = df.to_csv(index=False).encode("utf-8")
                z.writestr(f"{t}.csv", csv)
            except Exception as e:
                z.writestr(f"{t}__ERROR.txt", f"No se pudo exportar {t}: {e}")
    mem.seek(0)
    return mem



# Usa esto
@alt.theme.register('nice', enable=True)
def nice_theme():
    return alt.theme.ThemeConfig({
        "config": {"view": {"stroke": "transparent"}},
        "height": 400, "width": "container"
    })




# ============================
# 6) Arranque DB + Altair theme
# ============================

init_db()




# ============================
# 7) Navegación
# ============================

def sidebar():
    cfg = get_settings()
    rol = st.session_state["user"]["role"]

    st.sidebar.title("Menú principal")
    # Menú base
    paginas = ["Panel principal", "Ventas", "Productos"]

    # Si NO está en kiosco y es admin → mostrar todo
    if not cfg.get("kiosk_mode", False) and rol == "admin":
        paginas += ["Compras", "Gastos", "Reportes", "Configuración"]
    else:
        # En kiosco: ocultar páginas sensibles a no-admin
        if rol == "admin":
            paginas += ["Compras", "Gastos", "Reportes", "Configuración"]
        else:
            pass

    return st.sidebar.radio("Ir a:", paginas)


page = sidebar()

# Seguridad extra: si kiosco y no-admin, forzar salida de páginas restringidas
cfg = get_settings()
if cfg.get("kiosk_mode", False) and st.session_state["user"]["role"] != "admin":
    RESTRINGIDAS = {"Compras", "Gastos", "Reportes", "Configuración"}
    if page in RESTRINGIDAS:
        st.warning("Esta sección no está disponible en este dispositivo.")
        page = "Ventas"  # o "Panel principal"


# ============================
# 8) Páginas
# ============================

# --------- PANEL PRINCIPAL ---------
if page == "Panel principal":
    page_header("Panel principal", "Resumen del día y salud del negocio", icon="🏪")

    today0 = dt.datetime.now(dt.timezone.utc).date().isoformat()
    df_sales_today = df_read('SELECT * FROM sales WHERE "date"::date = ?', (today0,))
    df_items_today = df_read("""
        SELECT si.*, p.name
        FROM sale_items si
        JOIN products p ON p.id = si.product_id
        JOIN sales s ON s.id = si.sale_id
        WHERE s."date"::date = ?
    """, (today0,))
    df_exp_today = df_read('SELECT * FROM expenses WHERE "date"::date = ?', (today0,))


    sales_total = float(df_sales_today["total"].sum()) if not df_sales_today.empty else 0.0
    gross_profit = float((df_items_today["price"] - df_items_today["cost"]).mul(df_items_today["qty"]).sum()) if not df_items_today.empty else 0.0
    expenses_total = float(df_exp_today["amount"].sum()) if not df_exp_today.empty else 0.0
    net_profit = sales_total - expenses_total

    # ====== Series últimos 30 días para sparklines ======
    hoy_utc = pd.Timestamp.now(tz="UTC").normalize()
    ini_30 = (hoy_utc - pd.DateOffset(days=29)).date()
    fin_30 = hoy_utc.date()

    # Ventas por día
    df_sales_30 = df_read("""
        SELECT "date"::date AS d, SUM(total) AS t
        FROM sales
        WHERE "date"::date BETWEEN ? AND ?
        GROUP BY "date"::date
        ORDER BY "date"::date
    """, (ini_30.isoformat(), fin_30.isoformat()))
    df_sales_30.rename(columns={"d":"fecha", "t":"valor"}, inplace=True)

    # Utilidad bruta por día (sum((price - cost) * qty))
    df_gp_30 = df_read("""
        SELECT s."date"::date AS d, SUM((si.price - si.cost)*si.qty) AS u
        FROM sale_items si
        JOIN sales s ON s.id = si.sale_id
        WHERE s."date"::date BETWEEN ? AND ?
        GROUP BY s."date"::date
        ORDER BY s."date"::date
    """, (ini_30.isoformat(), fin_30.isoformat()))
    df_gp_30.rename(columns={"d":"fecha", "u":"valor"}, inplace=True)

    # Gastos por día
    df_exp_30 = df_read("""
        SELECT "date"::date AS d, SUM(amount) AS a
        FROM expenses
        WHERE "date"::date BETWEEN ? AND ?
        GROUP BY "date"::date
        ORDER BY "date"::date
    """, (ini_30.isoformat(), fin_30.isoformat()))
    df_exp_30.rename(columns={"d":"fecha", "a":"valor"}, inplace=True)

    # Aseguramos índice de fechas completo para evitar huecos visuales
    rng = pd.date_range(ini_30, fin_30, freq="D", tz=None)
    def _full_range(df):
        if df.empty:
            return pd.DataFrame({"fecha": rng, "valor": 0.0})
        tmp = df.copy()
        tmp["fecha"] = pd.to_datetime(tmp["fecha"])
        tmp = tmp.set_index("fecha").reindex(rng, fill_value=0.0).rename_axis("fecha").reset_index()
        return tmp

    sales_serie = _full_range(df_sales_30)
    gp_serie    = _full_range(df_gp_30)
    exp_serie   = _full_range(df_exp_30)

    # Ganancia neta = ventas - gastos (por día)
    net_serie = sales_serie.copy()
    net_serie["valor"] = sales_serie["valor"] - exp_serie["valor"]

    viz_cards([
    {"label":"Ventas de hoy","value":f"$ {sales_total:,.2f} MXN","icon":"💵",
     "series": sales_serie, "title":"Ventas ($)"},
    {"label":"Utilidad bruta","value":f"$ {gross_profit:,.2f} MXN","icon":"📈",
     "series": gp_serie, "title":"Utilidad ($)"},
    {"label":"Gastos de hoy","value":f"$ {expenses_total:,.2f} MXN","icon":"💳",
     "series": exp_serie, "title":"Gastos ($)"},
    {"label":"Ganancia neta","value":f"$ {net_profit:,.2f} MXN","icon":"💚",
     "series": net_serie, "title":"Neta ($)"},
    ], cols=4)



    section("Productos con bajo inventario", "🛎️")

    df_low = df_read("""
        SELECT * FROM products
        WHERE stock <= min_stock AND min_stock > 0
        ORDER BY stock ASC
    """)

    if df_low.empty:
        st.info("No hay alertas de inventario.")
    else:
        with framed_block():
            df_low = df_low.rename(columns={
                "name": "Producto",
                "sku": "Código",
                "stock": "Existencias",
                "min_stock": "Nivel mínimo de existencia",
                "price": "Precio"
            })
            st.dataframe(
                style_inventory(df_low[["Producto", "Código", "Existencias", "Nivel mínimo de existencia", "Precio"]]),
                width='stretch'
            )


    section("Ventas en el tiempo", "📈")
    with framed_block():
        inicio, fin, freq, date_fmt = period_controls("panel")


        df_ts = df_read("""
            SELECT s.date AS fecha, s.total
            FROM sales s
            WHERE s."date"::date BETWEEN ? AND ?
            ORDER BY s.date ASC
        """, (pd.to_datetime(inicio).date().isoformat(), pd.to_datetime(fin).date().isoformat()))

        if df_ts.empty:
            st.info("No hay ventas en el periodo seleccionado.")
        else:
            df_ts["fecha"] = pd.to_datetime(df_ts["fecha"])
            df_ts = df_ts.set_index("fecha").sort_index()
            serie = df_ts["total"].resample(freq).sum().rename("Total ($ MXN)").reset_index()
            date_fmt = "%d %b %Y" if freq in ("D","W") else "%b %Y"

            ts_chart(
                serie=serie,
                date_fmt=date_fmt,
                key_prefix="panel",
                x_col="fecha",
                y_col="Total ($ MXN)",
                y_title="Ingresos (MXN)",
                y_fmt="$,.2f"
            )



            total_periodo = float(serie["Total ($ MXN)"].sum())
            ini_txt = pd.to_datetime(inicio).strftime("%d %b %Y")
            fin_txt = pd.to_datetime(fin).strftime("%d %b %Y")
            st.caption(f"**Ingresos totales del periodo ({ini_txt} – {fin_txt}):** $ {total_periodo:,.2f} MXN")

# --------- VENTAS ---------
elif page == "Ventas":
    page_header("Registrar venta", "Agrega productos por nombre o escaneo de SKU", icon="🧾")
    show_flash()

    dfp = df_read("SELECT id, name, sku, price, stock, min_stock FROM products ORDER BY name ASC")
    if dfp.empty:
        with framed_block(): st.warning("Primero agrega productos en la sección **Productos**.")
    else:
        st.caption("Selecciona producto(s) y cantidad. El sistema descontará inventario automáticamente.")

        if "cart_qty" not in st.session_state: st.session_state.cart_qty = {}
        if "sel_productos" not in st.session_state: st.session_state.sel_productos = []

        def etiqueta_producto(pid: int) -> str:
            r = dfp[dfp["id"] == pid].iloc[0]
            alerta = " ⚠️ bajo stock" if (float(r["min_stock"]) > 0 and float(r["stock"]) <= float(r["min_stock"])) else ""
            return f"{r['name']} — $ {float(r['price']):.2f} — existencias: {int(float(r['stock']))}{alerta}"

        if st.session_state.get("reset_selector", False):
            st.session_state["sel_productos"] = []
            st.session_state["cart_qty"] = {}
            st.session_state["reset_selector"] = False

        with framed_block():
            def _add_sku_to_cart():
                sku = (st.session_state.get("sku_input") or "").strip()
                if not sku:
                    return
                row = dfp[dfp["sku"] == sku]
                if row.empty:
                    # Mensaje dentro del flujo + toast flotante
                    st.warning(f"Código/SKU '{sku}' no encontrado.")
                    st.toast(f"Código/SKU '{sku}' no encontrado.", icon="⚠️")
                    st.session_state["sku_input"] = ""
                    return

                r = row.iloc[0]; pid = int(r["id"]); stock = float(r["stock"])
                st.session_state.cart_qty = st.session_state.get("cart_qty", {})
                st.session_state.sel_productos = st.session_state.get("sel_productos", [])
                new_qty = min(st.session_state.cart_qty.get(pid, 0.0) + 1.0, float(stock))
                new_qty = float(max(new_qty, 0.0))
                if new_qty >= stock:
                    st.info(f"Se alcanzó el stock máximo para '{r['name']}' ({int(stock)} u.).")
                st.session_state.cart_qty[pid] = new_qty
                if pid not in st.session_state.sel_productos:
                    st.session_state.sel_productos.append(pid)
                st.session_state["sku_input"] = ""
                st.session_state["sku_last_added"] = int(pid)


            st.text_input(
                "Agregar por código / SKU",
                key="sku_input",
                placeholder="Escanea o escribe y presiona Enter",
                on_change=_add_sku_to_cart
            )
            _last = st.session_state.pop("sku_last_added", None)
            if _last is not None:
                try:
                    _name = dfp[dfp["id"] == _last]["name"].iloc[0]
                    st.toast(f"Agregado: {_name} (1 u.)", icon="✅")
                except Exception:
                    pass

            c_btn, c_sel = st.columns([1, 5])
            with c_btn:
                if st.session_state.get("sel_productos"):
                    if st.button("🧹 Limpiar", width='stretch'):
                        st.session_state["reset_selector"] = True
                        st.rerun()
            with c_sel:
                opciones = dfp["id"].tolist()
                st.multiselect(
                    "Selecciona productos",
                    options=opciones,
                    format_func=etiqueta_producto,
                    placeholder="Busca por nombre…",
                    key="sel_productos"
                )

        items = []; total = 0.0
        if st.session_state.sel_productos:
            with framed_block():
                for pid_saved in list(st.session_state.cart_qty.keys()):
                    if pid_saved not in st.session_state.sel_productos:
                        st.session_state.cart_qty.pop(pid_saved, None)

                st.subheader("Cantidad por producto")
                for pid in st.session_state.sel_productos:
                    r = dfp[dfp["id"] == pid].iloc[0]
                    col1, col2, col3, col4 = st.columns([4, 2, 2, 2])
                    col1.markdown(f"**{r['name']}**")
                    col2.markdown(f"Precio: `$ {float(r['price']):.2f}`")
                    stock_actual = float(r["stock"])
                    col3.markdown(f"Existencias: **{int(stock_actual)}**")
                    default_qty = st.session_state.cart_qty.get(int(pid), 1.0 if stock_actual >= 1 else 0.0)
                    qty = col4.number_input(
                        "Cantidad",
                        key=f"qty_{pid}",
                        min_value=0.0,
                        max_value=stock_actual,
                        step=1.0,
                        value=default_qty,
                        help="No puedes vender más de las existencias.",
                        disabled=(stock_actual == 0)
                    )
                    st.session_state.cart_qty[int(pid)] = float(qty)

                cfg = get_settings()
                iva_rate = float(cfg["iva_rate"])
                prices_include_iva = bool(cfg["prices_include_iva"])
                items = []; total = 0.0
                for pid, qty in st.session_state.cart_qty.items():
                    qty = float(qty)
                    if qty > 0:
                        row = dfp[dfp["id"] == pid].iloc[0]
                        base_price = float(row["price"])
                        gross_unit = base_price if prices_include_iva else base_price * (1.0 + iva_rate)
                        total += gross_unit * qty
                        items.append({"product_id": int(pid), "qty": qty})
                if items:
                    st.info(f"**Total estimado (con IVA):** $ {total:,.2f} MXN")

        c1p, c2p = st.columns(2)
        pay = c1p.selectbox("Método de pago", ["Efectivo", "Tarjeta", "Transferencia", "Otro"])
        note = c2p.text_input("Nota (opcional)")

        with framed_block():
            boton_etiqueta = "Registrar venta" if not items else f"Registrar venta — $ {total:,.2f} MXN"
            if st.button(boton_etiqueta, width='stretch', disabled=st.session_state.get("saving_sale", False)):
                if not items:
                    set_flash("⚠️ Agrega al menos un producto con cantidad > 0.", "warning", ttl=8)
                    st.rerun()
                else:
                    st.session_state["saving_sale"] = True
                    try:
                        with st.spinner("Guardando venta..."):
                            resultado = record_sale(items, pay, note)

                        if isinstance(resultado, dict) and resultado.get("ok"):
                            set_flash(f"✅ Venta #{resultado.get('sale_id')} registrada correctamente.", "success", ttl=8)
                            st.session_state.cart_qty.clear()
                            st.session_state.sel_productos.clear()
                            st.rerun()

                        elif isinstance(resultado, dict):
                            set_flash("❌ " + resultado.get("error", "No se pudo registrar la venta."), "error", ttl=10)
                            st.rerun()
                        else:
                            set_flash("❌ No se pudo registrar la venta.", "error", ttl=10)
                            st.rerun()
                    finally:
                        st.session_state["saving_sale"] = False



        section("Últimas ventas", "🧾")
        with framed_block():
            cfg = get_settings(); mon = cfg["currency"]
            dfl = df_read("""
                SELECT
                    s.id, s.date, s.subtotal, s.iva, s.total, s.payment_method, s.note,
                    SUM(si.qty) AS unidades_vendidas,
                    string_agg(p.name || ' x' || si.qty::text, ', ') AS detalle,
                    SUM((si.price - si.cost)*si.qty) AS utilidad
                FROM sales s
                JOIN sale_items si ON si.sale_id = s.id
                JOIN products p ON p.id = si.product_id
                GROUP BY s.id
                ORDER BY s.date DESC
                LIMIT 20
            """)
            if not dfl.empty:
                dfl = dfl.rename(columns={
                    "id":"ID","date":"Fecha", "subtotal":f"Subtotal ({mon})","iva":f"IVA ({mon})","total":f"Total ({mon})",
                    "payment_method":"Método de pago","note":"Nota","unidades_vendidas":"Cantidad vendida",
                    "detalle":"Detalle de productos","utilidad":f"Utilidad ({mon})"
                })

                # 👉 limpiar fecha para la vista (sin +00:00 ni microsegundos)
                dfl["Fecha"] = dfl["Fecha"].map(fmt_date_clean)

                st.dataframe(
                    dfl.style.format({
                        f"Subtotal ({mon})":"{:.2f}", f"IVA ({mon})":"{:.2f}", f"Total ({mon})":"{:.2f}",
                        f"Utilidad ({mon})":"{:.2f}",
                        "Cantidad vendida":"{:.0f}"
                    }),
                    width='stretch'
                )
            else:
                st.caption("Aún no hay ventas registradas.")


        # --- Ticket imprimible ---
        section("Ticket", "")
        with framed_block():
            sale_id_for_ticket = st.number_input("Folio de venta", min_value=1, step=1)
            cols = st.columns([1, 1, 1])

            if cols[1].button("Generar ticket (PDF)", width='stretch'):
                try:
                    pdf_bytes = build_receipt_pdf(int(sale_id_for_ticket))
                    st.download_button(
                        "⬇️ Descargar ticket (PDF)",
                        data=pdf_bytes,
                        file_name=f"ticket_{int(sale_id_for_ticket)}.pdf",
                        mime="application/pdf",
                        key=f"dl_ticket_{int(sale_id_for_ticket)}",
                        use_container_width=True
                    )
                except Exception as e:
                    st.error(f"Error al generar el PDF: {e}")

            # Reimpresión rápida
            if cols[2].button("🪶 Ver ticket directamente", width='stretch'):
                html = build_receipt_html(int(sale_id_for_ticket))
                st.components.v1.html(html, height=450, scrolling=True)


# --------- PRODUCTOS ---------
elif page == "Productos":
    page_header("Productos", "Alta, edición y control de inventario", icon="🧺")

    # Agregar producto
    with st.expander("➕ Agregar producto", expanded=False):
        with framed_block():
            name = st.text_input("Nombre del producto")
            sku = st.text_input("Código o SKU (opcional)")
            c1, c2, c3 = st.columns(3)
            price = c1.number_input("Precio de venta ($ MXN)", min_value=0.0, step=1.0)
            cost  = c2.number_input("Costo ($ MXN)", min_value=0.0, step=1.0)
            stock = c3.number_input("Existencias iniciales", min_value=0.0, step=1.0)
            c4, c5 = st.columns(2)
            min_stock = c4.number_input("Nivel mínimo de existencia", min_value=0.0, step=1.0)
            category  = c5.text_input("Categoría (opcional)")
            if st.button("Guardar producto", width='stretch'):
                if not name or price <= 0:
                    st.error("Nombre y precio son obligatorios.")
                else:
                    try:
                        add_product(name, price, cost, stock, min_stock, sku or None, category or None)
                        st.success("✅ Producto guardado correctamente.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error: {e}")

    # Editar producto
    with st.expander("✏️ Editar producto", expanded=False):
        dfp_edit = df_read("SELECT * FROM products ORDER BY name ASC")
        if dfp_edit.empty:
            with framed_block(): st.info("No hay productos aún.")
        else:
            with framed_block():
                sel_id = st.selectbox(
                    "Selecciona un producto",
                    options=dfp_edit["id"].tolist(),
                    format_func=lambda x: dfp_edit[dfp_edit["id"] == x]["name"].iloc[0]
                )
                row = dfp_edit[dfp_edit["id"] == sel_id].iloc[0]
                c1, c2 = st.columns(2)
                name_e = c1.text_input("Nombre", value=row["name"])
                sku_e  = c2.text_input("Código / SKU", value=row["sku"] or "")
                c3, c4, c5 = st.columns(3)
                price_e = c3.number_input("Precio de venta ($ MXN)", min_value=0.0, step=0.5, value=float(row["price"]))
                cost_e  = c4.number_input("Costo ($ MXN)", min_value=0.0, step=0.5, value=float(row["cost"]))
                stock_e = c5.number_input("Existencias", min_value=0.0, step=1.0, value=float(row["stock"]))
                c6, c7 = st.columns(2)
                min_e  = c6.number_input("Nivel mínimo de existencia", min_value=0.0, step=1.0, value=float(row["min_stock"]))
                cat_e  = c7.text_input("Categoría", value=row["category"] or "")
                st.caption("Nota: editar precio/costo afecta **ventas futuras**; el historial guardado no cambia.")

                # KPIs del producto
                kpi = df_read("""
                    SELECT
                        COALESCE(SUM(si.qty), 0)                              AS qty_total,
                        COALESCE(SUM(si.qty * si.price), 0)                   AS ingresos_netos,
                        COALESCE(SUM((si.price - si.cost) * si.qty), 0)       AS utilidad,
                        MAX(s.date)                                           AS ultima_venta
                    FROM sale_items si
                    JOIN sales s ON s.id = si.sale_id
                    WHERE si.product_id = ?
                """, (sel_id,))
                qty_total       = float(kpi.loc[0, "qty_total"] or 0)
                ingresos_netos  = float(kpi.loc[0, "ingresos_netos"] or 0.0)
                utilidad_total  = float(kpi.loc[0, "utilidad"] or 0.0)
                ultima_venta    = kpi.loc[0, "ultima_venta"]
                stock_actual    = float(row["stock"])
                minimo_actual   = float(row["min_stock"])
                cfg             = get_settings()
                mon             = cfg["currency"]

            section("Indicadores del producto", "📊")
            with framed_block():
                # Velocidad de venta (90d) y días de cobertura
                vel = df_read("""
                    SELECT s."date"::date AS d, SUM(si.qty) AS q
                    FROM sale_items si
                    JOIN sales s ON s.id = si.sale_id
                    WHERE si.product_id = ?
                    AND s."date"::date >= CURRENT_DATE - INTERVAL '90 day'
                    GROUP BY s."date"::date
                """, (sel_id,))
                vel_prom_dia = 0.0 if vel.empty else float(vel["q"].sum()) / max(len(vel), 1)
                dias_cobertura = None if vel_prom_dia <= 0 else stock_actual / vel_prom_dia

                stat_cards([
                    {"label":"Unidades vendidas (acum.)", "value":f"{qty_total:,.0f}", "icon":"📦"},
                    {"label":"Ingresos netos (acum.)", "value":f"{mon} {ingresos_netos:,.2f}", "icon":"💰"},
                    {"label":"Utilidad (acum.)", "value":f"{mon} {utilidad_total:,.2f}", "icon":"📈"},
                    {"label":"Última venta", "value":"-" if not ultima_venta else pd.to_datetime(ultima_venta).strftime("%d %b %Y"), "icon":"🕒"},
                ], cols=4)

                m5, m6, m7 = st.columns(3)
                m5.metric("Existencias actuales", f"{stock_actual:,.0f}")
                m6.metric("Nivel mínimo", f"{minimo_actual:,.0f}")
                m7.metric("Días de cobertura", "-" if dias_cobertura is None else f"{dias_cobertura:,.1f}")

            section("Ventas del producto en el tiempo", "📈")
            with framed_block():
                df_prod_ts = df_read("""
                    SELECT s."date"::date AS fecha, SUM(si.qty) AS cantidad, SUM(si.qty * si.price) AS ingresos_netos
                    FROM sale_items si
                    JOIN sales s ON s.id = si.sale_id
                    WHERE si.product_id = ?
                    AND s."date"::date >= CURRENT_DATE - INTERVAL '365 day'
                    GROUP BY s."date"::date
                    ORDER BY s."date"::date
                """, (sel_id,))
                if df_prod_ts.empty:
                    st.caption("No hay ventas registradas para este producto en el último año.")
                else:
                    df_prod_ts["fecha"] = pd.to_datetime(df_prod_ts["fecha"])
                    colg1, colg2 = st.columns([2,2])
                    metrica = colg1.selectbox("Métrica", ["Unidades vendidas", "Ingresos netos"], index=0)
                    suavizado = colg2.selectbox("Media móvil", ["Sin media", "7 días", "30 días"], index=0)
                    if metrica == "Unidades vendidas":
                        y_field, y_title, y_fmt = "cantidad", "Unidades", ",.0f"
                    else:
                        y_field, y_title, y_fmt = "ingresos_netos", f"Ingresos netos ({mon})", "$,.2f"

                    base = alt.Chart(df_prod_ts).properties(height=280)
                    x_enc = alt.X("fecha:T", title="Fecha", axis=alt.Axis(format="%d %b %Y"))
                    y_enc = alt.Y(f"{y_field}:Q", title=y_title, axis=alt.Axis(format=y_fmt))
                    line = base.mark_line().encode(x=x_enc, y=y_enc)
                    pts  = base.mark_point().encode(x=x_enc, y=y_enc)
                    tooltip = base.mark_rule(opacity=0).encode(
                        x=x_enc, y=y_enc,
                        tooltip=[alt.Tooltip("fecha:T", title="Fecha", format="%d %b %Y"),
                                 alt.Tooltip(f"{y_field}:Q", title=y_title, format=y_fmt)]
                    )
                    chart = line + pts + tooltip
                    if suavizado != "Sin media":
                        ventana = 7 if suavizado == "7 días" else 30
                        df_mm = df_prod_ts.copy()
                        df_mm["MM"] = df_mm[y_field].rolling(window=ventana, min_periods=1).mean()
                        mm = alt.Chart(df_mm).properties(height=280).mark_line(strokeDash=[6,4]).encode(
                            x=x_enc,
                            y=alt.Y("MM:Q", title=None, axis=alt.Axis(format=y_fmt)),
                            tooltip=[alt.Tooltip("MM:Q", title=f"Media móvil ({ventana})", format=y_fmt)]
                        )
                        chart = chart + mm
                   
                    st.altair_chart(chart, use_container_width=True)




            # Guardar cambios del producto
            with framed_block():
                if st.button("Guardar cambios", type="primary", width='stretch'):
                    if not name_e or float(price_e) <= 0:
                        st.error("El nombre y el precio son obligatorios y deben ser válidos.")
                    else:
                        res = update_product(
                            product_id=sel_id,
                            name=name_e.strip(),
                            sku=(sku_e.strip() or None),
                            price=price_e,
                            cost=cost_e,
                            stock=stock_e,
                            min_stock=min_e,
                            category=(cat_e.strip() or None)
                        )
                        if res is True:
                            st.success("✅ Producto actualizado correctamente.")
                            st.rerun()
                        else:
                            st.error("❌ " + res.get("error", "No se pudo actualizar el producto."))


    # --- INVENTARIO ACTUAL (VISTA AVANZADA) — REEMPLAZA TODO ESTE BLOQUE ---
    section("Inventario actual", "📦")
    with framed_block():
        dfp_all = df_read("SELECT * FROM products ORDER BY name ASC")

        if dfp_all.empty:
            st.caption("Sin productos para mostrar.")
        else:
            # --- FILTROS RÁPIDOS ---
            c1, c2, c3, c4 = st.columns([3, 2, 2, 2])
            q = c1.text_input("Buscar (nombre o SKU)", key="inv_q")

            cats_all = sorted(
                [str(c).strip() for c in dfp_all["category"].dropna().unique().tolist() if str(c).strip() != ""]
            )
            sel_cats = c2.multiselect("Categoría", options=cats_all, key="inv_sel_cats")

            only_low = c3.toggle("Solo bajo inventario", value=False, key="inv_only_low")

            ordenar = c4.selectbox(
                "Ordenar por",
                ["Nombre ↑", "Existencias ↑", "Existencias ↓", "Precio ↑", "Precio ↓", "Código ↑"],
                index=0,
                key="inv_sort"
            )

            # --- APLICAR FILTROS ---
            df = dfp_all.copy()

            if q:
                ql = q.strip().lower()
                df = df[
                    df["name"].str.lower().str.contains(ql)
                    | df["sku"].fillna("").str.lower().str.contains(ql)
                ]

            if sel_cats:
                df = df[df["category"].isin(sel_cats)]

            if only_low:
                df = df[(df["min_stock"] > 0) & (df["stock"] <= df["min_stock"])]

            # --- ORDEN ---
            if ordenar == "Nombre ↑":
                df = df.sort_values("name", kind="stable")
            elif ordenar == "Existencias ↑":
                df = df.sort_values("stock", kind="stable")
            elif ordenar == "Existencias ↓":
                df = df.sort_values("stock", ascending=False, kind="stable")
            elif ordenar == "Precio ↑":
                df = df.sort_values("price", kind="stable")
            elif ordenar == "Precio ↓":
                df = df.sort_values("price", ascending=False, kind="stable")
            elif ordenar == "Código ↑":
                df = df.sort_values("sku", na_position="last", kind="stable")


            # --- DISPLAY BONITO ---
            df_show = df.rename(columns={
                "id": "ID",
                "name": "Producto",
                "sku": "Código",
                "price": "Precio ($)",
                "cost": "Costo ($)",
                "stock": "Existencias",
                "min_stock": "Nivel mínimo de existencia",
                "category": "Categoría",
            })

            st.dataframe(
                style_inventory(df_show),
                width='stretch'
            )

            # --- RESUMEN + EXPORTACIÓN ---
            total_refs = int(len(df))
            total_stock = float(df["stock"].sum())
            st.caption(f"Mostrando **{total_refs}** productos · Existencias totales: **{total_stock:,.0f}** u.")

            csv = df_show.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇️ Exportar vista filtrada (CSV)",
                data=csv,
                file_name="inventario_filtrado.csv",
                mime="text/csv",
                key="dl_inv_csv",
                width='stretch'
            )

        # ============================
        # AJUSTAR EXISTENCIAS MANUALMENTE
        # ============================
        st.subheader("Ajustar existencias manualmente")

        col1, col2 = st.columns([3, 2])
        with col1:
            pid = st.number_input("ID del producto", step=1, min_value=1, key="adj_id")
        with col2:
            new_stock = st.number_input("Nuevo stock", step=1.0, min_value=0.0, key="adj_stock")

        if st.button("Guardar nuevo stock", width='stretch'):
            dfp = df_read("SELECT id FROM products WHERE id=?", (pid,))
            if dfp.empty:
                st.warning("⚠️ No se encontró ningún producto con ese ID.")
            else:
                exec_sql("UPDATE products SET stock=? WHERE id=?", (new_stock, pid))
                st.success("✅ Stock actualizado correctamente.")
                st.rerun()

# ============================
# FIN DE SECCIÓN INVENTARIO
# ============================

# --------- COMPRAS ---------
elif page == "Compras":
    require_admin()
    page_header("Registrar compra", "Entrada de mercancía al inventario", icon="📥")

    dfp = df_read("SELECT id, name, stock, cost FROM products ORDER BY name ASC")
    if dfp.empty:
        with framed_block(): st.info("Primero crea productos en **Productos**.")
    else:
        with framed_block():
            proveedor = st.text_input("Proveedor (opcional)")
            nota = st.text_input("Nota (opcional)")

            st.caption("Selecciona productos a comprar y define cantidad/costo unitario.")
            if "buy_sel" not in st.session_state: st.session_state.buy_sel = []
            if "buy_qty" not in st.session_state: st.session_state.buy_qty = {}
            if "buy_cost" not in st.session_state: st.session_state.buy_cost = {}

            def fmt_opt(pid:int) -> str:
                r = dfp[dfp["id"]==pid].iloc[0]
                return f"{r['name']} — stock: {int(float(r['stock']))} — costo actual: $ {float(r['cost']):.2f}"

            opciones = dfp["id"].tolist()
            st.session_state.buy_sel = st.multiselect(
                "Productos a comprar", options=opciones, format_func=fmt_opt, default=st.session_state.buy_sel
            )

            total_compra = 0.0
            if st.session_state.buy_sel:
                st.subheader("Renglones de compra")
                with framed_block():
                    for pid in st.session_state.buy_sel:
                        r = dfp[dfp["id"]==pid].iloc[0]
                        c1,c2,c3,c4 = st.columns([4,2,2,2])
                        c1.markdown(f"**{r['name']}** (ID {int(r['id'])})")
                        qty = c2.number_input("Cantidad", key=f"buy_qty_{pid}", min_value=0.0, step=1.0, value=float(st.session_state.buy_qty.get(pid, 1.0)))
                        cost = c3.number_input("Costo unitario $", key=f"buy_cost_{pid}", min_value=0.0, step=0.5, value=float(st.session_state.buy_cost.get(pid, float(r['cost']) or 0.0)))
                        c4.markdown(f"**Importe:** $ {qty*cost:,.2f}")
                        st.session_state.buy_qty[pid] = float(qty)
                        st.session_state.buy_cost[pid] = float(cost)
                        total_compra += qty*cost

                st.info(f"**Total de la compra:** $ {total_compra:,.2f} MXN")

                cA, cB, cC = st.columns([1,1,2])
                crea_gasto = cA.toggle("Registrar también como Gasto", value=True, help="Creará un gasto 'Compras' por el total.")
                act_cost  = cB.toggle("Actualizar costo del producto", value=True)
                if cC.button("Guardar compra", width='stretch'):
                    items = []
                    for pid in st.session_state.buy_sel:
                        q = float(st.session_state.buy_qty.get(pid, 0.0))
                        c = float(st.session_state.buy_cost.get(pid, 0.0))
                        if q > 0 and c >= 0:
                            items.append({"product_id": int(pid), "qty": q, "cost": c})
                    if not items:
                        st.error("Agrega al menos un renglón con cantidad > 0.")
                    else:
                        res = record_purchase(items, supplier=(proveedor or None), note=(nota or ""), create_expense=crea_gasto, update_cost=act_cost)
                        if res is True:
                            st.success("✅ Compra registrada y stock actualizado.")
                            # limpiar estado
                            st.session_state.buy_sel.clear()
                            st.session_state.buy_qty.clear()
                            st.session_state.buy_cost.clear()
                            st.rerun()
                        else:
                            st.error(f"❌ {res.get('error','No se pudo registrar la compra.')}")

        section("Últimas compras", "🧾")
        with framed_block():
            dfl = df_read("""
                SELECT
                    p.id, p.date, p.supplier, p.total,
                    string_agg(pr.name || ' x' || pi.qty::text || ' @ $' || pi.cost::text, ', ') AS detalle
                FROM purchases p
                JOIN purchase_items pi ON pi.purchase_id = p.id
                JOIN products pr ON pr.id = pi.product_id
                GROUP BY p.id
                ORDER BY p.date DESC
                LIMIT 20
            """)
            if dfl.empty:
                st.caption("Sin compras registradas.")
            else:
                dfl = dfl.rename(columns={"id":"ID","date":"Fecha","supplier":"Proveedor","total":"Total ($ MXN)","detalle":"Detalle"})
                st.dataframe(dfl.style.format({"Total ($ MXN)":"{:.2f}"}), width='stretch')

# --------- GASTOS ---------
elif page == "Gastos":
    require_admin()
    page_header("Gastos", "Registra egresos operativos", icon="💳")

    with framed_block():
        c1,c2 = st.columns([2,1])
        cat = c1.text_input("Categoría", value="Servicios", placeholder="Renta, Luz, Nómina, Etc.")
        amt = c2.number_input("Monto ($ MXN)", min_value=0.0, step=1.0)
        note = st.text_input("Nota (opcional)")
        if st.button("Guardar gasto", width='stretch'):
            if amt <= 0:
                st.error("El monto debe ser > 0.")
            else:
                record_expense(cat or "Gasto", amt, note or "")
                st.success("✅ Gasto registrado.")
                st.rerun()

    section("Gastos recientes", "🧾")
    with framed_block():
        hoy = pd.Timestamp.now(tz="UTC").normalize().date()
        hace30 = (pd.Timestamp(hoy) - pd.DateOffset(days=30)).date()
        dfe = df_read('SELECT id, "date" as fecha, category, amount, note FROM expenses WHERE "date"::date BETWEEN ? AND ? ORDER BY "date" DESC',
                      (hace30.isoformat(), hoy.isoformat()))
        if dfe.empty:
            st.caption("No hay gastos en los últimos 30 días.")
        else:
            tot = float(dfe["amount"].sum())
            st.metric("Total 30 días", f"$ {tot:,.2f} MXN")
            st.dataframe(dfe.rename(columns={"id":"ID","fecha":"Fecha","category":"Categoría","amount":"Monto ($ MXN)","note":"Nota"}).style.format({"Monto ($ MXN)":"{:.2f}"}), width='stretch')

# --------- REPORTES ---------
elif page == "Reportes":
    require_admin()
    page_header("Reportes", "Ventas, gastos y utilidad por periodo", icon="📊")

    inicio, fin, freq, date_fmt = period_controls("reportes", default_period="Últimos 3 meses")

    # Series de ventas (total), gastos (amount) y utilidad neta (ventas - gastos)
    df_ventas = df_read("""
        SELECT s."date"::date AS d, SUM(s.total) AS v
        FROM sales s
        WHERE s."date"::date BETWEEN ? AND ?
        GROUP BY s."date"::date
        ORDER BY s."date"::date
    """, (pd.to_datetime(inicio).date().isoformat(), pd.to_datetime(fin).date().isoformat()))
    df_gastos = df_read("""
        SELECT e."date"::date AS d, SUM(e.amount) AS g
        FROM expenses e
        WHERE e."date"::date BETWEEN ? AND ?
        GROUP BY e."date"::date
        ORDER BY e."date"::date
    """, (pd.to_datetime(inicio).date().isoformat(), pd.to_datetime(fin).date().isoformat()))

    # Reamostrar
    def _resample_sum(df, col, freq):
        if df.empty:
            return pd.DataFrame({"fecha": [], "valor": []})
        tmp = df.rename(columns={"d":"fecha", col:"valor"})
        tmp["fecha"] = pd.to_datetime(tmp["fecha"])
        tmp = tmp.set_index("fecha").sort_index().resample(freq).sum().reset_index()
        return tmp

    serie_v = _resample_sum(df_ventas, "v", freq).rename(columns={"valor":"Total ($ MXN)"})
    serie_g = _resample_sum(df_gastos, "g", freq).rename(columns={"valor":"Total ($ MXN)"})
    # utilidad neta
    serie_n = pd.merge(
        serie_v[["fecha","Total ($ MXN)"]].rename(columns={"Total ($ MXN)":"ventas"}),
        serie_g[["fecha","Total ($ MXN)"]].rename(columns={"Total ($ MXN)":"gastos"}),
        on="fecha", how="outer"
    ).fillna(0.0)
    serie_n["Total ($ MXN)"] = serie_n["ventas"] - serie_n["gastos"]
    serie_n = serie_n[["fecha","Total ($ MXN)"]]

    section("Ventas en el periodo", "💵")
    with framed_block():
        if serie_v.empty:
            st.caption("Sin datos de ventas.")
        else:
            ts_chart(serie_v, date_fmt, key_prefix="rep_v", y_title="Ingresos (MXN)", y_fmt="$,.2f")

    section("Gastos en el periodo", "💸")
    with framed_block():
        if serie_g.empty:
            st.caption("Sin datos de gastos.")
        else:
            ts_chart(serie_g, date_fmt, key_prefix="rep_g", y_title="Egresos (MXN)", y_fmt="$,.2f")

    section("Utilidad neta", "✅")
    with framed_block():
        if serie_n.empty:
            st.caption("Sin datos para utilidad neta.")
        else:
            ts_chart(serie_n, date_fmt, key_prefix="rep_n", y_title="Utilidad (MXN)", y_fmt="$,.2f")

    
    # Exportables
    section("Exportar datos", "⬇️")
    with framed_block():
        df_exp_sales = build_sales_export(inicio, fin)
        df_exp_purch = build_purchases_export(inicio, fin)

        if df_exp_sales.empty and df_exp_purch.empty:
            st.caption("No hay datos en el rango.")
        else:
            # --- Ventas ---
            if not df_exp_sales.empty:
                # 1) Versión 'limpia' para visualizar en pantalla
                df_exp_sales_view = df_exp_sales.copy()
                if "Fecha" in df_exp_sales_view.columns:
                    df_exp_sales_view["Fecha"] = df_exp_sales_view["Fecha"].map(fmt_date_clean)

                # 2) Botón de descarga (CSV crudo, sin alterar)
                csv_download(
                    df_exp_sales,
                    _date_range_filename("ventas", inicio, fin),
                    "⬇️ Ventas (CSV)",
                    preview=False  # evitamos que csv_download pinte una segunda tabla
                )

                # 3) Tabla en pantalla con fechas limpias
                st.dataframe(df_exp_sales_view, width='stretch')

            # --- Compras ---
            if not df_exp_purch.empty:
                df_exp_purch_view = df_exp_purch.copy()
                if "Fecha" in df_exp_purch_view.columns:
                    df_exp_purch_view["Fecha"] = df_exp_purch_view["Fecha"].map(fmt_date_clean)

                csv_download(
                    df_exp_purch,
                    _date_range_filename("compras", inicio, fin),
                    "⬇️ Compras (CSV)",
                    preview=False
                )
                st.dataframe(df_exp_purch_view, width='stretch')


# --------- CONFIGURACIÓN ---------
elif page == "Configuración":
    require_admin()
    page_header("Configuración", "Parámetros del sistema", icon="⚙️")

    cfg = get_settings()
    with framed_block():
        c1,c2 = st.columns(2)
        negocio = c1.text_input("Nombre del negocio", value=cfg.get("business_name","Mi Negocio"))
        moneda  = c2.text_input("Moneda (display)", value=cfg.get("currency","$ MXN"))

        c3,c4,c5 = st.columns(3)
        iva_rate = c3.number_input("IVA (0.00–1.00)", min_value=0.0, max_value=1.0, step=0.01, value=float(cfg.get("iva_rate",0.16)))
        incluyen = c4.toggle("Precios incluyen IVA", value=bool(cfg.get("prices_include_iva", True)))
        metodo   = c5.selectbox("Método de costo", ["ultimo","promedio_ponderado"], index=0 if cfg.get("cost_method","ultimo")=="ultimo" else 1)

        c6,c7 = st.columns(2)
        kiosk  = c6.toggle("Modo kiosco (oculta menús sensibles a no-admin)", value=bool(cfg.get("kiosk_mode", False)))
        diag   = c7.toggle("Mostrar diagnósticos de BD", value=bool(cfg.get("show_db_diag", False)))

        if st.button("Guardar configuración", width='stretch'):
            try:
                set_setting("business_name", negocio.strip() or "Mi Negocio")
                set_setting("currency", moneda.strip() or "$ MXN")
                set_setting("iva_rate", str(float(iva_rate)))
                set_setting("prices_include_iva", "true" if incluyen else "false")
                set_setting("cost_method", metodo)
                set_setting("kiosk_mode", "true" if kiosk else "false")
                set_setting("show_db_diag", "true" if diag else "false")
                st.success("✅ Configuración guardada.")
                st.rerun()
            except Exception as e:
                st.error(f"Error guardando configuración: {e}")

else:
    # Fallback por si el texto en el radio cambia y no hay bloque
    page_header("Sección no implementada", "Aún no hay contenido para esta página.", icon="ℹ️")
    st.info("Elige una opción disponible en el menú.")
