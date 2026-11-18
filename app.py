import os, ipaddress, secrets
from datetime import datetime, timezone
from functools import wraps
from contextlib import contextmanager
from urllib.parse import urlparse
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
from flask import Flask, request, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_cors import CORS
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from dotenv import load_dotenv

load_dotenv()
APP_SECRET = os.getenv('APP_SECRET', '')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '')
DATABASE_URL = os.getenv('DATABASE_URL', '')
ALLOWED_ORIGINS = [x.strip().rstrip('/') for x in os.getenv('ALLOWED_ORIGINS', '').split(',') if x.strip()]
PUBLIC_SITE_URL = os.getenv('PUBLIC_SITE_URL', '').rstrip('/')
if len(APP_SECRET) < 32 or not ADMIN_PASSWORD or not DATABASE_URL:
    raise RuntimeError('Set APP_SECRET (32+ chars), ADMIN_PASSWORD and DATABASE_URL.')

app = Flask(__name__)
# Render sits behind a trusted reverse proxy and supplies forwarded client metadata.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
CORS(app, resources={r'/api/*': {'origins': ALLOWED_ORIGINS}}, supports_credentials=False)
serializer = URLSafeTimedSerializer(APP_SECRET, salt='tracepoint-admin-v1')

@contextmanager
def db():
    url = DATABASE_URL
    if url.startswith('postgres://'):
        url = 'postgresql://' + url[len('postgres://'):]
    conn = psycopg2.connect(url, sslmode='require', cursor_factory=RealDictCursor)
    try:
        with conn:
            yield conn
    finally:
        conn.close()

def init_db():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('''CREATE TABLE IF NOT EXISTS links (
                id BIGSERIAL PRIMARY KEY, token VARCHAR(80) UNIQUE NOT NULL,
                label VARCHAR(70) NOT NULL, created TIMESTAMPTZ NOT NULL DEFAULT NOW())''')
            cur.execute('''CREATE TABLE IF NOT EXISTS visits (
                id BIGSERIAL PRIMARY KEY, link_id BIGINT NOT NULL REFERENCES links(id) ON DELETE CASCADE,
                visited TIMESTAMPTZ NOT NULL DEFAULT NOW(), city VARCHAR(160), region VARCHAR(160),
                country VARCHAR(160), country_code VARCHAR(8), latitude DOUBLE PRECISION,
                longitude DOUBLE PRECISION, timezone VARCHAR(160), network VARCHAR(160))''')
            cur.execute('CREATE INDEX IF NOT EXISTS visits_link_id_idx ON visits(link_id)')

def client_ip():
    # Trust Cloudflare's client IP only when the request also has a Cloudflare Ray header.
    if request.headers.get('CF-Ray') and request.headers.get('CF-Connecting-IP'):
        return request.headers['CF-Connecting-IP'].split(',')[0].strip()
    return (request.remote_addr or '').strip()

def geo_lookup(ip):
    try:
        if not ipaddress.ip_address(ip).is_global:
            return {}
    except ValueError:
        return {}
    try:
        r = requests.get(f'https://ipapi.co/{ip}/json/', timeout=7,
                         headers={'User-Agent': 'Tracepoint-Demo/1.0'})
        r.raise_for_status()
        data = r.json()
        if data.get('error'):
            return {}
        return data
    except requests.RequestException:
        return {}

def short(value):
    return str(value)[:160] if value not in (None, '') else None

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        header = request.headers.get('Authorization', '')
        if not header.startswith('Bearer '):
            return jsonify(error='Authentication required.'), 401
        try:
            payload = serializer.loads(header[7:], max_age=43200)
            if payload.get('role') != 'admin': raise BadSignature('invalid role')
        except SignatureExpired:
            return jsonify(error='Session expired. Please sign in again.'), 401
        except BadSignature:
            return jsonify(error='Invalid session.'), 401
        return fn(*args, **kwargs)
    return wrapped

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    return response

@app.get('/api/health')
def health():
    try:
        with db() as conn:
            with conn.cursor() as cur: cur.execute('SELECT 1')
        return jsonify(status='ok', database='connected')
    except Exception:
        app.logger.exception('Health check failed')
        return jsonify(status='error', database='unavailable'), 503

@app.post('/api/admin/login')
def login():
    body = request.get_json(silent=True) or {}
    supplied = str(body.get('password', ''))
    import hmac
    if not hmac.compare_digest(supplied, ADMIN_PASSWORD):
        return jsonify(error='Incorrect password.'), 401
    token = serializer.dumps({'role': 'admin'})
    return jsonify(token=token, expires_in=43200)

@app.post('/api/visit')
def visit():
    body = request.get_json(silent=True) or {}
    token = str(body.get('token', ''))[:80]
    if not token:
        return jsonify(error='Missing link token.'), 400
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT id, label FROM links WHERE token=%s', (token,))
            link = cur.fetchone()
            if not link: return jsonify(error='This link is invalid or no longer active.'), 404
            # IP is used transiently for approximate geolocation and is never stored.
            data = geo_lookup(client_ip())
            try:
                lat = float(data['latitude']) if data.get('latitude') is not None else None
                lon = float(data['longitude']) if data.get('longitude') is not None else None
            except (TypeError, ValueError):
                lat, lon = None, None
            cur.execute('''INSERT INTO visits
                (link_id, city, region, country, country_code, latitude, longitude, timezone, network)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (link['id'], short(data.get('city')), short(data.get('region')),
                 short(data.get('country_name')), short(data.get('country_code')),
                 lat, lon, short(data.get('timezone')), short(data.get('org'))))
    return jsonify(ok=True, label=link['label'])

@app.get('/api/admin/overview')
@admin_required
def overview():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT l.id,l.token,l.label,l.created,COUNT(v.id)::int AS visits
                           FROM links l LEFT JOIN visits v ON v.link_id=l.id
                           GROUP BY l.id ORDER BY l.id DESC''')
            links = cur.fetchall()
            cur.execute('''SELECT v.id,v.visited,v.city,v.region,v.country,v.country_code,
                           v.latitude,v.longitude,v.timezone,v.network,l.label,l.token
                           FROM visits v JOIN links l ON l.id=v.link_id
                           ORDER BY v.id DESC LIMIT 200''')
            visits = cur.fetchall()
            cur.execute('SELECT COUNT(*)::int AS total, COUNT(DISTINCT country_code)::int AS countries FROM visits')
            stats = cur.fetchone()
    for row in links:
        row['created'] = row['created'].isoformat()
        row['url'] = f"{PUBLIC_SITE_URL}/?t={row['token']}" if PUBLIC_SITE_URL else f"/?t={row['token']}"
    for row in visits:
        row['visited'] = row['visited'].isoformat()
    return jsonify(links=links, visits=visits, stats=stats)

@app.post('/api/admin/links')
@admin_required
def create_link():
    body = request.get_json(silent=True) or {}
    label = str(body.get('label', '')).strip()[:70]
    if not label: return jsonify(error='Enter a name for this link.'), 400
    token = secrets.token_urlsafe(12)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('INSERT INTO links(token,label) VALUES(%s,%s) RETURNING id,token,label,created', (token,label))
            row = cur.fetchone()
    row['created'] = row['created'].isoformat()
    row['url'] = f'{PUBLIC_SITE_URL}/?t={token}' if PUBLIC_SITE_URL else f'/?t={token}'
    row['visits'] = 0
    return jsonify(link=row), 201

@app.delete('/api/admin/links/<int:link_id>')
@admin_required
def delete_link(link_id):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('DELETE FROM links WHERE id=%s RETURNING id', (link_id,))
            deleted = cur.fetchone()
    if not deleted: return jsonify(error='Link not found.'), 404
    return jsonify(ok=True)

@app.errorhandler(500)
def internal_error(_):
    return jsonify(error='An internal server error occurred.'), 500

init_db()
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5000')), debug=False)
