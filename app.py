from flask import Flask, jsonify, request, make_response

from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies
)

from flask_restplus import Resource, Api, fields
import secure

# NOTE: This is just a basic example of how to enable cookies. This is
#       vulnerable to CSRF attacks, and should not be used as is. See
#       csrf_protection_with_cookies.py for a more complete example!


app = Flask(__name__)
api = Api(app)

# Configure application to store JWTs in cookies. Whenever you make
# a request to a protected endpoint, you will need to send in the
# access or refresh JWT via a cookie.
app.config['JWT_TOKEN_LOCATION'] = ['cookies']

# Set the cookie paths, so that you are only sending your access token
# cookie to the access endpoints, and only sending your refresh token
# to the refresh endpoint. Technically this is optional, but it is in
# your best interest to not send additional cookies in the request if
# they aren't needed.
app.config['JWT_ACCESS_COOKIE_PATH'] = '/api/'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh'

# Disable CSRF protection for this example. In almost every case,
# this is a bad idea. See examples/csrf_protection_with_cookies.py
# for how safely store JWTs in cookies
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

# Set the secret key to sign the JWTs with
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!

jwt = JWTManager(app)

# Use the set_access_cookie() and set_refresh_cookie() on a response
# object to set the JWTs in the response cookies. You can configure
# the cookie names and other settings via various app.config options

ns = api.namespace('token', description='Operations related to blog categories')

xy = ns.model('auth', {
    'username': fields.String(attribute='username'),
    'password': fields.String(attribute='password')
})

yz = ns.model('refresh', {
    'xy': fields.String(attribute='xy'),
})

userDict = {} # initialize users at startup - fetch this from db

## This is used to register a new user
@ns.route('/register')
class Register(Resource):
    @ns.expect(xy)
    def post(self):
        try:
            username = request.json.get('username', None)
            password = request.json.get('password', None)
        except Exception:
            resp = jsonify({'register': False})
            return make_response(resp, 400)

        if username in userDict.keys():
            resp = jsonify({'register': False, 'message': f'Username {username} already exists'})
            return make_response(resp, 400)
        else:
            userDict[username] = secure.hash_password(password)
            resp = jsonify({'register': True, 'message': f'Welcome, {username}!'})
            return make_response(resp, 200)
            

# This is used to login and get a JWT inside a cookie to access further things or the API
@ns.route('/auth')
class Login(Resource):
    @ns.expect(xy)
    def post(self):
        # try to get data from json # todo - or formpost
        try:
            username = request.json.get('username', None)
            password = request.json.get('password', None)
        except Exception:
            resp = jsonify({'login': False, 'message': f'Please provide username and password in json format.'})
            return make_response(resp, 403)
        
        if username in userDict.keys():
            if secure.verify_password(userDict[username], password):
                pass
            else:
                #TODO log
                return make_response(jsonify({'login': False, "message": f"Wrong password for {username}"}), 401)
        else:
            #TODO log
            return make_response(jsonify({'login': False, "message": f"User {username} unknown"}), 401)

        # Create the tokens we will be sending back to the user
        access_token = create_access_token(identity=username, user_claims=[{ 'meh': 123 }])
        refresh_token = create_refresh_token(identity=username)

        # Set the JWT cookies in the response
        resp = jsonify({'login': True, 'message': f'Hello, {username}!'})
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        #TODO log
        return make_response(resp, 200)


# Same thing as login here, except we are only setting a new cookie
# for the access token.
@ns.route('/refresh')
class Refresh(Resource):
    @jwt_refresh_token_required
    @ns.expect(yz)
    def post(self):
        # Create the new access token
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)

        # Set the JWT access cookie in the response
        resp = jsonify({'refresh': True})
        set_access_cookies(resp, access_token)
        return resp, 200


# Because the JWTs are stored in an httponly cookie now, we cannot
# log the user out by simply deleting the cookie in the frontend.
# We need the backend to send us a response to delete the cookies
# in order to logout. unset_jwt_cookies is a helper function to
# do just that.
@ns.route('/remove')
class Logout(Resource):
    def post(self):
        resp = jsonify({'logout': True})
        unset_jwt_cookies(resp)
        return resp, 200


# We do not need to make any changes to our protected endpoints. They
# will all still function the exact same as they do when sending the
# JWT in via a header instead of a cookie
@app.route('/api/example', methods=['GET'])
@jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify({'hello': 'from {}'.format(username)}), 200


if __name__ == '__main__':
    app.run()
