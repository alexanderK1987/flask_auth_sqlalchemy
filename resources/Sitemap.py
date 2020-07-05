import flask
import flask_cors
import operator
from app import app

@app.route('/api', methods=['GET'])
def routes():
    rules = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(sorted(rule.methods))
        rules.append({'endpoint': rule.endpoint, 'methods': methods, 'api': str(rule)})

    rules = sorted(rules, key=operator.itemgetter('api')) 
    return flask.jsonify(rules)
