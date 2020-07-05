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
@jwt_required
def rwd_user_by_id(_id):
    try:
        userSchema = UserSchema()
        q = User.query.get_or_404(_id,
            description='User with _id=%d does not exists...' % _id)
        
        if flask.request.method == 'GET':
            return flask.jsonify(userSchema.dump(q))

        elif flask.request.method == 'PUT':
            # check who i am
            login_id = get_jwt_identity()
            login_user = User.query.get(login_id)

            # a user can only modify an account profile only if:
            # (1) it is an admin, or (2) it is itself
            # TODO: may need to create a function for access right checking
            if (login_user._id != _id) and (login_user.username != 'admin'):
                return flask.jsonify({'msg': '(%d, %s) is not authorized to change user profile (%d, %s)' % (login_user._id, login_user.username, q._id, q.username)})

            _json = flask.request.get_json(force=True)
            putting = userSchema.load(_json)
            locked_fields = ('username', 'password', '_id', 'active')
            for attr in putting:
                if attr in locked_fields:
                    pass
                elif hasattr(q, attr):
                    setattr(q, attr, putting[attr])
            
            db.session.commit()
            return '', 204
            
        elif flask.request.method == 'DELETE':
            # check who i am
            login_id = get_jwt_identity()
            login_user = User.query.get(login_id)

            # admin cannot be deleted
            if q.username == 'admin':
                return flask.jsonify({'msg': 'admin cannot be deleted'}), 403

            # a user can only modify an account profile only if:
            # (1) it is an admin, or (2) it is itself
            # TODO: may need to create a function for access right checking
            if (login_user._id != _id) and (login_user.username != 'admin'):
                return flask.jsonify({'msg': '(%d, %s) is not authorized to delete user profile (%d, %s)' % (login_user._id, login_user.username, q._id, q.username)}), 403

            db.session.delete(q)
            db.session.commit()
            return '', 204
            
        else:
            return flask.jsonify({'msg': '%s not implemented yet' % flask.request.method}), 501
    
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
        # check name uniqueness
        q = User.query.filter_by(username=_json['username']).first()
        if q is not None:
             return flask.jsonify({'msg': 'User with name %s already exists...' % _json['username']}), 400

        # insert
        db.session.add(_inserting)
        db.session.commit()
        return flask.jsonify({'msg': 'user %s created' % (_inserting.username), '_id': _inserting._id}), 201

    except Exception as e:
        return flask.jsonify({'msg': str(e)}), 500

# login
@app.route('/auth/login', methods=['POST'])
def login():
    try: 
        _json = flask.request.get_json(force=True)

        # username and password are not provided
        if ('username' not in _json) or ('password' not in _json):
            return flask.jsonify({'msg': 'you must provide username and password'}), 400
            
        q = User.query.filter_by(username=_json['username']).first_or_404(
             description='User with name %s does not exists...' % _json['username'])

        if not User.verify_hash(_json['password'], q.password):
             return flask.jsonify({'msg': 'wrong credentials'}), 422

        # Create our JWTs
        access_token = create_access_token(identity=q._id)
        refresh_token = create_refresh_token(identity=q._id)

        return flask.jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 201

    except Exception as e:
        return flask.jsonify({'msg': str(e)}), 500

# activate an account
@app.route('/auth/activate/<int:_id>', methods=['GET', 'POST'])
@jwt_required
def activate_user(_id):
    try:
        # check who i am
        login_id = get_jwt_identity()
        login_user = User.query.get(login_id)

        # TODO: may need to create a function for access right checking
        if login_user.username != 'admin':
            return flask.jsonify({'msg': 'only admin can activate/deactivate users'}), 403
        
        q = User.query.get_or_404(_id,
            description='User with _id=%d does not exists...' % _id)

        q.active = 1
        db.sesion.commit()
        return '', 204

    except Exception as e:
        return flask.jsonify({'msg': str(e)}), 500

# deactivate an account
@app.route('/auth/deactivate/<int:_id>', methods=['GET', 'POST'])
@jwt_required
def deactivate_user(_id):
    try:
        # check who i am
        login_id = get_jwt_identity()
        login_user = User.query.get(login_id)

        # TODO: may need to create a function for access right checking
        if login_user.username != 'admin':
            return flask.jsonify({'msg': 'only admin can activate/deactivate users'}), 403
        
        q = User.query.get_or_404(_id,
            description='User with _id=%d does not exists...' % _id)

        # admin cannot be deactivated
        if q.username == 'admin':
            return flask.jsonify({'msg': 'admin cannot be deactivated'}), 403

        q.active = 0
        db.sesion.commit()
        return '', 204

    except Exception as e:
        return flask.jsonify({'msg': str(e)}), 500


# get a new access toke by refreshing
@app.route('/auth/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    try:
        # Do the same thing that we did in the login endpoint here
        login_id = get_jwt_identity()
        access_token = create_access_token(identity=login_id)
        return flask.jsonify({'access_token': access_token}), 201

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
        return flask.jsonify({"msg": "Access token revoked"})

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
        return flask.jsonify({"msg": "Refresh token revoked"})

    except Exception as e:
        return flask.jsonify({'msg': str(e)}), 500

# query who i am
@app.route('/auth/whoami', methods=['GET'])
@jwt_required
def whoami():
    try:
        login_id = get_jwt_identity()
        q = User.query.get(login_id)
        userSchema = UserSchema()
        return flask.jsonify(userSchema.dump(q))

    except Exception as e:
        return flask.jsonify({'msg': str(e)}), 500        
