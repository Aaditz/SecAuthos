from marshmallow import Schema, fields, validate
class RegisterSchema(Schema): name=fields.Str(required=True, validate=validate.Length(min=2,max=120)); email=fields.Email(required=True); password=fields.Str(required=True, load_only=True, validate=validate.Length(min=12,max=128))
class LoginSchema(Schema): email=fields.Email(required=True); password=fields.Str(required=True, load_only=True); totp=fields.Str(load_default=None, validate=validate.Length(equal=6)); remember_me=fields.Bool(load_default=False)
class PasswordSchema(Schema): password=fields.Str(required=True, load_only=True, validate=validate.Length(min=12,max=128))
class ChangePasswordSchema(Schema): current_password=fields.Str(required=True, load_only=True); new_password=fields.Str(required=True, load_only=True, validate=validate.Length(min=12,max=128))
class MFAConfirmSchema(Schema): code=fields.Str(required=True, validate=validate.Length(equal=6))
class ProfileSchema(Schema): name=fields.Str(validate=validate.Length(min=2,max=120))
