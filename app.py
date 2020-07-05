import datetime

import flask
import flask_cors
import flask_jwt_extended 
import flask_marshmallow
import flask_migrate
import flask_script
import flask_sqlalchemy

# initialize flask app
app = flask.Flask(__name__)
app.config.from_pyfile("config.py")

# cors
cors = flask_cors.CORS(app)

# security
jwt = flask_jwt_extended.JWTManager(app)

# models and schemas
db = flask_sqlalchemy.SQLAlchemy(app)
ma = flask_marshmallow.Marshmallow(app)

# migration
manager = flask_script.Manager(app)
migrate = flask_migrate.Migrate(app, db, compare_type=True)

import resources.Auth
import resources.Sitemap

# hello function
@app.route('/')
def root():
    return flask.jsonify({'timestamp': datetime.datetime.now().isoformat(), 'msg': 'hello'}), 200

if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0', port=5000, threaded=True)

    except KeyboardInterrupt:
        pass 

    print ('exiting ...')

