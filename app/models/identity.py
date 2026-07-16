import uuid
from datetime import datetime, timezone
from sqlalchemy import UniqueConstraint
from app.extensions import db

def now(): return datetime.now(timezone.utc)
def utc(value):
    """Normalize database datetimes; SQLite drops timezone offsets in tests."""
    return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value
def uid(): return str(uuid.uuid4())

user_roles = db.Table("user_roles", db.Column("user_id", db.String(36), db.ForeignKey("users.id"), primary_key=True), db.Column("role_id", db.String(36), db.ForeignKey("roles.id"), primary_key=True))
role_permissions = db.Table("role_permissions", db.Column("role_id", db.String(36), db.ForeignKey("roles.id"), primary_key=True), db.Column("permission_id", db.String(36), db.ForeignKey("permissions.id"), primary_key=True))

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(36), primary_key=True, default=uid); email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False); name = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False); is_email_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_admin_locked = db.Column(db.Boolean, default=False, nullable=False); locked_until = db.Column(db.DateTime(timezone=True)); failed_login_count = db.Column(db.Integer, default=0, nullable=False)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False); mfa_secret = db.Column(db.Text); recovery_code_hashes = db.Column(db.JSON, default=list)
    password_changed_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False); created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False); last_login_at = db.Column(db.DateTime(timezone=True))
    roles = db.relationship("Role", secondary=user_roles, back_populates="users")
    def has_permission(self, permission): return any(permission in {p.name for p in role.permissions} for role in self.roles)

class Role(db.Model):
    __tablename__ = "roles"; id = db.Column(db.String(36), primary_key=True, default=uid); name = db.Column(db.String(50), unique=True, nullable=False); description = db.Column(db.String(255))
    users = db.relationship("User", secondary=user_roles, back_populates="roles"); permissions = db.relationship("Permission", secondary=role_permissions, back_populates="roles")
class Permission(db.Model):
    __tablename__ = "permissions"; id = db.Column(db.String(36), primary_key=True, default=uid); name = db.Column(db.String(100), unique=True, nullable=False); description = db.Column(db.String(255))
    roles = db.relationship("Role", secondary=role_permissions, back_populates="permissions")
class RefreshToken(db.Model):
    __tablename__ = "refresh_tokens"; id = db.Column(db.String(36), primary_key=True, default=uid); user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True); jti = db.Column(db.String(36), unique=True, nullable=False, index=True); expires_at = db.Column(db.DateTime(timezone=True), nullable=False); revoked_at = db.Column(db.DateTime(timezone=True)); session_id = db.Column(db.String(36), db.ForeignKey("user_sessions.id")); created_at = db.Column(db.DateTime(timezone=True), default=now)
class BlocklistedToken(db.Model):
    __tablename__ = "blocklisted_tokens"; jti = db.Column(db.String(36), primary_key=True); expires_at = db.Column(db.DateTime(timezone=True), nullable=False); reason = db.Column(db.String(100)); created_at = db.Column(db.DateTime(timezone=True), default=now)
class UserSession(db.Model):
    __tablename__ = "user_sessions"; id = db.Column(db.String(36), primary_key=True, default=uid); user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True); ip_address = db.Column(db.String(45)); user_agent = db.Column(db.String(512)); device_fingerprint = db.Column(db.String(128)); created_at = db.Column(db.DateTime(timezone=True), default=now); last_seen_at = db.Column(db.DateTime(timezone=True), default=now); expires_at = db.Column(db.DateTime(timezone=True), nullable=False); terminated_at = db.Column(db.DateTime(timezone=True))
class AuditLog(db.Model):
    __tablename__ = "audit_logs"; id = db.Column(db.String(36), primary_key=True, default=uid); user_id = db.Column(db.String(36), db.ForeignKey("users.id"), index=True); event = db.Column(db.String(100), nullable=False); ip_address = db.Column(db.String(45)); metadata_json = db.Column(db.JSON, default=dict); created_at = db.Column(db.DateTime(timezone=True), default=now, index=True)
class PasswordHistory(db.Model):
    __tablename__ = "password_history"; id = db.Column(db.String(36), primary_key=True, default=uid); user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True); password_hash = db.Column(db.String(128), nullable=False); created_at = db.Column(db.DateTime(timezone=True), default=now)
class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"; id = db.Column(db.String(36), primary_key=True, default=uid); email = db.Column(db.String(254), index=True); ip_address = db.Column(db.String(45), index=True); successful = db.Column(db.Boolean, nullable=False); created_at = db.Column(db.DateTime(timezone=True), default=now)
class TrustedDevice(db.Model):
    __tablename__ = "trusted_devices"; id = db.Column(db.String(36), primary_key=True, default=uid); user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False); fingerprint = db.Column(db.String(128), nullable=False); label = db.Column(db.String(120)); trust_score = db.Column(db.Integer, default=50); approved_at = db.Column(db.DateTime(timezone=True), default=now); __table_args__=(UniqueConstraint("user_id", "fingerprint"),)
class ActionToken(db.Model):
    __tablename__ = "action_tokens"; id = db.Column(db.String(36), primary_key=True, default=uid); user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False); purpose = db.Column(db.String(40), nullable=False); token_hash = db.Column(db.String(128), unique=True, nullable=False); expires_at = db.Column(db.DateTime(timezone=True), nullable=False); used_at = db.Column(db.DateTime(timezone=True))
