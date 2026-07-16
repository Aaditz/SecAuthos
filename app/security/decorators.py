from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from app.models import User
def permission_required(permission):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            verify_jwt_in_request(); user = User.query.get(get_jwt_identity())
            if not user or not user.has_permission(permission): return jsonify(error="forbidden", message="Required permission missing."), 403
            return fn(*args, **kwargs)
        return wrapped
    return decorator
