import flask
import datetime

from app import app, jwt, db
from models.UserModel import (User, RevokedToken)
from models.UserSchema import UserSchema
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token, get_jti,
    jwt_refresh_token_required, get_jwt_identity, jwt_required, get_raw_jwt
)
from passlib.hash import pbkdf2_sha256 as sha256

# TODO: init auth db if key users do not exist
default_users = {'admin': 'nimda', 'guest': 'guest'}

@jwt.token_in_blacklist_loader
def check_if_token_is_revoked(decrypted_token):
    jti = decrypted_token['jti']
    return RevokedToken.is_jti_blacklisted(jti)

# get all users
@app.route('/user', methods=['GET'])
@jwt_required
def get_users():
    try:
        userSchema = UserSchema(many=True)
        q = User.query.all()
        return flask.jsonify(userSchema.dump(q))

    except Exception as e:
        return flask.jsonify({'msg': str(e)}), 500


@app.route('/user/<int:_id>', methods=['GET', 'PUT', 'DELETE'])
def rwd_user_by_id(_id):
    try:
        userSchema = UserSchema()
        q = User.query.get_or_404(_id)
        
        if flask.request.method == 'GET':
            return flask.jsonify(userSchema.dump(q))

        else:
            return flask.jsonify({'msg': '%s not implemented yet ...' % flask.request.method})
    
    except Exception as e:
        return flask.jsonify({'msg': str(e)}), 500

# register
@app.route('/user', methods=['POST'])
@app.route('/auth/register', methods=['POST'])
def create_user():
    try:
        _json = flask.request.get_json(force=True)
        _inserting = User(
            username =_json['username'],
            password = User.generate_hash(_json['password'])
        )
        # check name
        q = User.query.filter_by(username=_json['username']).first()
        if q is not None:
             return flask.jsonify({'msg': 'User with name %s already exists...' % _json['username']}), 500

        # insert
        db.session.add(_inserting)
        db.session.commit()
        return flask.jsonify({'msg': 'user created'}), 201

    except Exception as e:
        return flask.jsonify({'msg': str(e)}), 500


# login
@app.route('/auth/login', methods=['POST'])
def login():
    try: 
        _json = flask.request.get_json(force=True)

        # username and password are not provided
        if ('username' not in _json) or ('password' not in _json):
            return flask.jsonify({'msg': 'you must provide username and password ...'}), 400
            
        q = User.query.filter_by(username=_json['username']).first_or_404(
             description='User with name %s does not exists...' % _json['username'])

        if not User.verify_hash(_json['password'], q.password):
             return flask.jsonify({'msg': 'wrong credentials ...'}), 422

        # Create our JWTs
        access_token = create_access_token(identity=q._id)
        refresh_token = create_refresh_token(identity=q._id)

        access_jti = get_jti(encoded_token=access_token)
        refresh_jti = get_jti(encoded_token=refresh_token)

        ret = {'access_token': access_token, 'refresh_token': refresh_token}
        return flask.jsonify(ret), 200

    except Exception as e:
        return flask.jsonify({'msg': str(e)}), 500


# get a new access toke by refreshing
@app.route('/auth/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    try:
        # Do the same thing that we did in the login endpoint here
        _id = get_jwt_identity()
        access_token = create_access_token(identity=_id)
        access_jti = get_jti(encoded_token=access_token)
        
        ret = {'access_token': access_token}
        return flask.jsonify(ret), 201

    except Exception as e:
        return flask.jsonify({'msg': str(e)}), 500


# revoke the current users access token
@app.route('/auth/access', methods=['DELETE'])
@jwt_required
def logout_access():
    try:
        jti = get_raw_jwt()['jti']
        revoked_token = RevokedToken(jti=jti)
        revoked_token.add()
        return flask.jsonify({"msg": "Access token revoked"}), 200

    except Exception as e:
        return flask.jsonify({'msg': str(e)}), 500


# revoke the current users refresh token
@app.route('/auth/refresh', methods=['DELETE'])
@jwt_refresh_token_required
def logout_refresh():
    try:
        jti = get_raw_jwt()['jti']
        revoked_token = RevokedToken(jti=jti)
        revoked_token.add()
        return flask.jsonify({"msg": "Refresh token revoked"}), 200

    except Exception as e:
        return flask.jsonify({'msg': str(e)}), 500


# query who am i
@app.route('/auth/whoami', methods=['GET'])
@jwt_required
def whoami():
    _id = get_jwt_identity()
    userSchema = UserSchema()
    q = User.query.get(_id)
    return flask.jsonify(userSchema.dump(q)), 200


