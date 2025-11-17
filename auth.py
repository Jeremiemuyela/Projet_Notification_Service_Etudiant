"""
Module d'authentification et d'autorisation simple
Stockage des utilisateurs dans un fichier JSON
"""
import json
import os
import secrets
import hashlib
from typing import Dict, List, Optional, Set
from functools import wraps
from flask import request, jsonify, session, redirect, url_for
from db import get_conn

# Fichier de stockage des utilisateurs
USERS_FILE = "users.json"

# Rôles disponibles
ROLES = {
    "admin": {"description": "Administrateur complet", "permissions": ["*"]},
    "operator": {"description": "Opérateur", "permissions": ["read", "send_notifications"]},
    "viewer": {"description": "Lecteur", "permissions": ["read"]}
}


def load_users() -> Dict[str, Dict]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, password_hash, role, api_key, active FROM users")
    users: Dict[str, Dict] = {}
    for row in cur.fetchall():
        users[row[0]] = {
            "username": row[0],
            "password_hash": row[1],
            "role": row[2],
            "api_key": row[3],
            "active": bool(row[4]),
        }
    conn.close()
    return users


def save_users(users: Dict[str, Dict]):
    conn = get_conn()
    cur = conn.cursor()
    for _, u in users.items():
        cur.execute(
            "INSERT INTO users(username, password_hash, role, api_key, active) VALUES(?,?,?,?,?) "
            "ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, role=excluded.role, api_key=excluded.api_key, active=excluded.active",
            (
                u.get("username"),
                u.get("password_hash"),
                u.get("role", "viewer"),
                u.get("api_key"),
                1 if u.get("active", True) else 0,
            ),
        )
    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    """Hash un mot de passe avec SHA-256 (simple, pour développement)."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    """Vérifie un mot de passe contre son hash."""
    return hash_password(password) == hashed


def generate_api_key() -> str:
    """Génère une clé API aléatoire."""
    return secrets.token_urlsafe(32)


def create_user(username: str, password: str, role: str = "viewer", api_key: Optional[str] = None) -> Dict:
    if role not in ROLES:
        raise ValueError(f"Rôle invalide: {role}. Rôles disponibles: {', '.join(ROLES.keys())}")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username=?", (username,))
    if cur.fetchone():
        conn.close()
        raise ValueError(f"L'utilisateur '{username}' existe déjà")
    if api_key is None:
        api_key = generate_api_key()
    user = {
        "username": username,
        "password_hash": hash_password(password),
        "role": role,
        "api_key": api_key,
        "active": True,
    }
    cur.execute(
        "INSERT INTO users(username, password_hash, role, api_key, active) VALUES(?,?,?,?,?)",
        (username, user["password_hash"], role, api_key, 1),
    )
    conn.commit()
    conn.close()
    return user


def authenticate_user(username: str, password: str) -> Optional[Dict]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, password_hash, role, api_key, active FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    user = {
        "username": row[0],
        "password_hash": row[1],
        "role": row[2],
        "api_key": row[3],
        "active": bool(row[4]),
    }
    if not user.get("active", True):
        return None
    if not verify_password(password, user.get("password_hash", "")):
        return None
    return user


def authenticate_api_key(api_key: str) -> Optional[Dict]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, password_hash, role, api_key, active FROM users WHERE api_key=?", (api_key,))
    row = cur.fetchone()
    conn.close()
    if row and bool(row[4]):
        return {
            "username": row[0],
            "password_hash": row[1],
            "role": row[2],
            "api_key": row[3],
            "active": bool(row[4]),
        }
    return None


def get_user_permissions(role: str) -> Set[str]:
    """Récupère les permissions d'un rôle."""
    role_data = ROLES.get(role, {})
    permissions = set(role_data.get("permissions", []))
    
    # "*" signifie toutes les permissions
    if "*" in permissions:
        return {"*"}
    
    return permissions


def has_permission(user: Dict, permission: str) -> bool:
    """Vérifie si un utilisateur a une permission spécifique."""
    role = user.get("role", "viewer")
    permissions = get_user_permissions(role)
    
    return "*" in permissions or permission in permissions


# ==================== DÉCORATEURS ====================

def require_auth(f):
    """Décorateur pour exiger une authentification (session ou API key)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Vérifier la session (pour l'interface web)
        if 'user' in session:
            return f(*args, **kwargs)
        
        # Vérifier la clé API (pour les requêtes API)
        api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')
        if api_key:
            user = authenticate_api_key(api_key)
            if user:
                request.current_user = user
                return f(*args, **kwargs)
        
        # Pas d'authentification valide
        if request.path.startswith('/admin'):
            return redirect(url_for('admin.login'))
        else:
            return jsonify({
                "success": False,
                "error": "Authentification requise",
                "message": "Veuillez fournir une clé API valide dans l'en-tête X-API-Key ou vous connecter"
            }), 401
    
    return decorated_function


def require_role(*allowed_roles):
    """Décorateur pour exiger un rôle spécifique."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = None
            
            # Récupérer l'utilisateur depuis la session ou la requête
            if 'user' in session:
                user = session['user']
            elif hasattr(request, 'current_user'):
                user = request.current_user
            else:
                if request.path.startswith('/admin'):
                    return redirect(url_for('admin.login'))
                else:
                    return jsonify({
                        "success": False,
                        "error": "Authentification requise"
                    }), 401
            
            user_role = user.get('role', 'viewer')
            if user_role not in allowed_roles:
                return jsonify({
                    "success": False,
                    "error": "Accès refusé",
                    "message": f"Rôle requis: {', '.join(allowed_roles)}. Votre rôle: {user_role}"
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def require_permission(permission: str):
    """Décorateur pour exiger une permission spécifique."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = None
            
            if 'user' in session:
                user = session['user']
            elif hasattr(request, 'current_user'):
                user = request.current_user
            else:
                if request.path.startswith('/admin'):
                    return redirect(url_for('admin.login'))
                else:
                    return jsonify({
                        "success": False,
                        "error": "Authentification requise"
                    }), 401
            
            if not has_permission(user, permission):
                return jsonify({
                    "success": False,
                    "error": "Permission refusée",
                    "message": f"Permission requise: {permission}"
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


# ==================== INITIALISATION ====================

def init_default_users():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(1) FROM users")
        count = cur.fetchone()[0]
        if count == 0:
            create_user(username="admin", password="admin123", role="admin")
            print("[AUTH] Utilisateur admin créé (mot de passe: admin123)")
            print("[AUTH] Changez le mot de passe en production !")
        conn.close()
    except Exception as e:
        print(f"[AUTH] Erreur lors de l'initialisation: {e}")

