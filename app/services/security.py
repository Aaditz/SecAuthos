import hashlib, secrets, re
from datetime import timedelta
import bcrypt, pyotp
from flask import current_app, request
from flask_jwt_extended import create_access_token, create_refresh_token, decode_token
from app.extensions import db
from app.models import User, PasswordHistory, AuditLog, UserSession, RefreshToken, BlocklistedToken
from app.models.identity import now, utc

PASSWORD_RULE = re.compile(r"(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s])")
def hash_password(password): return bcrypt.hashpw((password + current_app.config["PASSWORD_PEPPER"]).encode(), bcrypt.gensalt(rounds=12)).decode()
def verify_password(password, hashed): return bcrypt.checkpw((password + current_app.config["PASSWORD_PEPPER"]).encode(), hashed.encode())
def validate_password(password):
    if len(password) < 12 or not PASSWORD_RULE.search(password): raise ValueError("Password must be 12+ characters and include uppercase, lowercase, number, and special character.")
def audit(event, user_id=None, **metadata):
    db.session.add(AuditLog(user_id=user_id, event=event, ip_address=request.remote_addr, metadata_json=metadata))
def is_reused(user, password): return any(verify_password(password, p.password_hash) for p in PasswordHistory.query.filter_by(user_id=user.id).order_by(PasswordHistory.created_at.desc()).limit(5))
def set_password(user, password):
    validate_password(password)
    if is_reused(user, password): raise ValueError("Password was used recently.")
    user.password_hash = hash_password(password); user.password_changed_at = now(); db.session.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash))
def issue_tokens(user, remember_me=False):
    session = UserSession(user_id=user.id, ip_address=request.remote_addr, user_agent=request.user_agent.string[:512], device_fingerprint=request.headers.get("X-Device-Fingerprint", "")[:128], expires_at=now()+timedelta(days=30 if remember_me else 1))
    db.session.add(session); db.session.flush()
    claims = {"sid": session.id, "roles": [r.name for r in user.roles]}
    access = create_access_token(identity=user.id, additional_claims=claims)
    refresh = create_refresh_token(identity=user.id, additional_claims=claims, expires_delta=timedelta(days=30 if remember_me else 14))
    payload = decode_token(refresh); db.session.add(RefreshToken(user_id=user.id, jti=payload["jti"], session_id=session.id, expires_at=now()+timedelta(days=30 if remember_me else 14)))
    return access, refresh
def revoke_jti(jti, exp, reason="logout"):
    if not BlocklistedToken.query.get(jti): db.session.add(BlocklistedToken(jti=jti, expires_at=exp, reason=reason))
def security_score(user):
    score = 0; tips=[]
    if user.mfa_enabled: score += 30
    else: tips.append("Enable multi-factor authentication (+30)")
    if user.is_email_verified: score += 10
    else: tips.append("Verify your email (+10)")
    if user.failed_login_count == 0: score += 10
    if user.recovery_code_hashes: score += 10
    else: tips.append("Save MFA recovery codes (+10)")
    if (now()-utc(user.password_changed_at)).days < 90: score += 20
    else: tips.append("Update your password (+20)")
    return score, tips
def generate_recovery_codes(): return [secrets.token_urlsafe(7).upper() for _ in range(10)]
def mfa_uri(user): return pyotp.TOTP(user.mfa_secret).provisioning_uri(name=user.email, issuer_name="SecAuthos")
