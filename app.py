import json
import pdb
from flask import Flask, request, jsonify, make_response, g
from pymongo import MongoClient, ReturnDocument
from bson import Binary, Code
from bson.json_util import dumps
from flask_restful import Resource, Api

import bcrypt

app = Flask(__name__)
mongo = MongoClient('mongodb://kaichi:password@ds155325.mlab.com:55325/trip_planner_production')
# mongo = MongoClient('mongodb://localhost:27017/')

app.db = mongo.trip_planner_production
api = Api(app)

app.bcrypt_rounds = 12

def validate_auth(user, password):
    user_collection = app.db.users
    user = user_collection.find_one({'username': user})

    if user is None:
        return False
    else:
        # check if the hash we generate based on auth matches stored hash
        encodedPassword = password.encode('utf-8')
        if bcrypt.hashpw(encodedPassword, user['password']) == user['password']:
            g.setdefault('user', user)
            return True
        else:
            return False

def authenticated_request(func):
    def wrapper(*args, **kwargs):
        auth = request.authorization

        if not auth or not validate_auth(auth.username, auth.password):
            return ({'error': 'Basic Auth Required.'}, 401, None)

        return func(*args, **kwargs)

    return wrapper

class Users(Resource):

    def __init__(self):
        self.users_collection = app.db.users

    def post(self):
        json_body = request.json
        password = json_body['password']
        username = json_body['username']
        json_body['id'] = self.users_collection.count()

        encodedPassword = password.encode('utf-8')
        hashed = bcrypt.hashpw(encodedPassword, bcrypt.gensalt(app.bcrypt_rounds))
        # hashed = hashed.decode()

        json_body['password'] = hashed

        result = self.users_collection.insert_one(json_body)
        user = self.users_collection.find_one({"username": username})
        return user

    @authenticated_request
    def get(self):
        # user = g.get('user', None)
        # user.pop('password')
        username = request.authorization.username
        user = self.users_collection.find_one({"username": username})
        # pdb.set_trace()
        return user

    @authenticated_request
    def patch(self):
        username = request.authorization.username
        new_user = request.json["new_username"]
        user = self.users_collection.find_one_and_update(
            {"username": username},
            {"$set": {"username": new_user}},
            return_document=ReturnDocument.AFTER
        )
        return user

    @authenticated_request
    def delete(self):
        username = request.authorization.username
        self.users_collection.remove({'username': username})


class Trip(Resource):

    def __init__(self):
        self.trip_collection = app.db.trips

    def post(self):
        new_trip = request.json
        # trip_collection = app.db.trip
        result = self.trip_collection.insert_one(new_trip)
        trip = self.trip_collection.find_one({"_id": result.inserted_id})
        return trip

    def get(self):
        user_id = request.args.get('id', type=int)
        # trip_collection = app.db.trip
        trip = self.trip_collection.find({'id': user_id})
        return trip

    def patch(self):
        user_id = request.args.get('id', type=int)
        old_trip = request.args.get('old_trip')

        # waypoint = request.args.get('row')
        new_trip = request.args.get('new_trip')
        new_waypoint = request.args.get('new_waypoint', type=[str])
        trip = self.trip_collection.find_one_and_update(
            {'id': user_id, 'trip_name': old_trip},
            {"$set": {'trip_name': new_trip,
                      'waypoints': new_waypoint}},
            return_document=ReturnDocument.AFTER
        )
        return trip

    def delete(self):
        user_id = request.args.get('id', type=int)
        trip_name = request.args.get('trip_name')
        # trip_collection = app.db.trip
        row_of_waypoint = request.args.get('row')
        waypoint = request.args.get('waypoint')

        if row_of_waypoint is not None and waypoint is not None:
            trip = self.trip_collection.find_one_and_update(
                {'id': user_id, 'trip_name': trip_name},
                {"$pull": {'waypoints': {'{}'.format(row_of_waypoint): waypoint}}},
                return_document=ReturnDocument.AFTER
            )
            return trip
        else:
            self.trip_collection.remove({'id': user_id, 'trip_name': trip_name})


@api.representation('application/json')
def output_json(data, code, headers=None):
    resp = make_response(dumps(data), code)
    resp.headers.extend(headers or {})
    return resp


api.add_resource(Users, '/users')
api.add_resource(Trip, '/trip')
#api.add_resource(Trip, '/trip', "/<trip_id>")


if __name__ == '__main__':
    # Turn this on in debug mode to get detailled information about request related exceptions: http://flask.pocoo.org/docs/0.10/config/
    app.config['TRAP_BAD_REQUEST_ERRORS'] = True
    app.run(debug=True)
