from datetime import timedelta
import base64
from io import BytesIO
import pyotp
import qrcode
from flask import request
from flask_smorest import Blueprint, abort
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity, decode_token
from app.extensions import db
from app.models import User, Role, LoginAttempt, RefreshToken
from app.models.identity import now
from app.schemas.auth import RegisterSchema, LoginSchema, PasswordSchema, ChangePasswordSchema, MFAConfirmSchema
from app.services.security import hash_password, verify_password, validate_password, set_password, audit, issue_tokens, revoke_jti, generate_recovery_codes, mfa_uri
blp=Blueprint("auth", __name__, url_prefix="/api/v1/auth", description="Authentication and identity lifecycle")

@blp.route("/register", methods=["POST"])
@blp.arguments(RegisterSchema)
@blp.response(201)
def register(data):
    if User.query.filter_by(email=data["email"].lower()).first(): abort(409, message="An account with this email already exists.")
    try: validate_password(data["password"])
    except ValueError as e: abort(400, message=str(e))
    role=Role.query.filter_by(name="User").first()
    user=User(email=data["email"].lower(), name=data["name"], password_hash=hash_password(data["password"]), roles=[role] if role else [])
    db.session.add(user); db.session.flush(); set_password(user, data["password"]); audit("registration", user.id); db.session.commit()
    return {"message":"Registration complete. Verify your email before sensitive actions.","user_id":user.id}

@blp.route("/login", methods=["POST"])
@blp.arguments(LoginSchema)
@blp.response(200)
def login(data):
    user=User.query.filter_by(email=data["email"].lower()).first(); success=False
    if not user or not verify_password(data["password"], user.password_hash):
        if user: user.failed_login_count += 1; user.locked_until=now()+timedelta(minutes=30) if user.failed_login_count >= 5 else None
        db.session.add(LoginAttempt(email=data["email"].lower(),ip_address=request.remote_addr,successful=False)); audit("login_failed", user.id if user else None); db.session.commit(); abort(401, message="Invalid credentials.")
    if user.is_admin_locked or not user.is_active or (user.locked_until and user.locked_until > now()): abort(423, message="Account is locked.")
    if user.mfa_enabled and (not data.get("totp") or not pyotp.TOTP(user.mfa_secret).verify(data["totp"], valid_window=1)): abort(401, message="Valid MFA code required.")
    user.failed_login_count=0; user.locked_until=None; user.last_login_at=now(); db.session.add(LoginAttempt(email=user.email,ip_address=request.remote_addr,successful=True)); audit("login",user.id); access,refresh=issue_tokens(user,data["remember_me"]); db.session.commit()
    return {"access_token":access,"refresh_token":refresh,"token_type":"Bearer"}

@blp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    payload=get_jwt(); user=User.query.get(get_jwt_identity()); record=RefreshToken.query.filter_by(jti=payload["jti"]).first()
    if not user or not record or record.revoked_at: abort(401,message="Refresh token revoked.")
    record.revoked_at=now(); revoke_jti(payload["jti"], now()+timedelta(days=14),"rotation"); access,refresh_token=issue_tokens(user); audit("token_rotated",user.id); db.session.commit()
    return {"access_token":access,"refresh_token":refresh_token,"token_type":"Bearer"}

@blp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    p=get_jwt(); revoke_jti(p["jti"],now()+timedelta(minutes=15)); audit("logout",get_jwt_identity()); db.session.commit(); return {"message":"Logged out."}

@blp.route("/password/change", methods=["POST"])
@jwt_required()
@blp.arguments(ChangePasswordSchema)
def change_password(data):
    user=User.query.get_or_404(get_jwt_identity())
    if not verify_password(data["current_password"],user.password_hash): abort(401,message="Current password is incorrect.")
    try: set_password(user,data["new_password"])
    except ValueError as e: abort(400,message=str(e))
    audit("password_changed",user.id); db.session.commit(); return {"message":"Password changed. Re-authenticate on other devices."}

@blp.route("/mfa/setup", methods=["POST"])
@jwt_required()
def mfa_setup():
    user=User.query.get_or_404(get_jwt_identity()); user.mfa_secret=pyotp.random_base32(); db.session.commit()
    uri = mfa_uri(user); image = qrcode.make(uri); buffer = BytesIO(); image.save(buffer, format="PNG")
    return {"secret":user.mfa_secret,"otpauth_uri":uri,"qr_code_data_uri":"data:image/png;base64,"+base64.b64encode(buffer.getvalue()).decode()}
@blp.route("/mfa/confirm", methods=["POST"])
@jwt_required()
@blp.arguments(MFAConfirmSchema)
def mfa_confirm(data):
    user=User.query.get_or_404(get_jwt_identity())
    if not user.mfa_secret or not pyotp.TOTP(user.mfa_secret).verify(data["code"],valid_window=1): abort(400,message="Invalid authenticator code.")
    codes=generate_recovery_codes(); user.recovery_code_hashes=[hash_password(c) for c in codes]; user.mfa_enabled=True; audit("mfa_enabled",user.id); db.session.commit(); return {"recovery_codes":codes}
@blp.route("/mfa", methods=["DELETE"])
@jwt_required()
@blp.arguments(MFAConfirmSchema)
def mfa_disable(data):
    user=User.query.get_or_404(get_jwt_identity())
    if not pyotp.TOTP(user.mfa_secret or "").verify(data["code"],valid_window=1): abort(400,message="Invalid authenticator code.")
    user.mfa_enabled=False; user.mfa_secret=None; user.recovery_code_hashes=[]; audit("mfa_disabled",user.id); db.session.commit(); return {"message":"MFA disabled."}
