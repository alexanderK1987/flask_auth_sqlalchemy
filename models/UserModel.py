import flask 
from app import (db)
from passlib.hash import pbkdf2_sha256 as sha256

class User(db.Model):
    __tablename__ = "users"

    # authentication
    _id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Unicode(64), unique=True, nullable=False, index=True)
    password = db.Column(db.String(128), nullable=False)
    realname = db.Column(db.Unicode(64), index=True)

    # profile data
    address = db.Column(db.Text)
    mobile_phone = db.Column(db.Text)
    email = db.Column(db.Text)
    
    # activation
    active = db.Column(db.Integer)

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

class RevokedToken(db.Model):
    __tablename = 'revoked_tokens'
    _id = db.Column(db.Integer, primary_key = True)
    jti = db.Column(db.String(128))

    def add(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti = jti).first()
        return bool(query)
