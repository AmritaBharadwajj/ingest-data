import os
from threading import Thread
from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from passlib.hash import pbkdf2_sha256
from flask_oauthlib.provider import OAuth2Provider
from passlib.hash import pbkdf2_sha256
from oauth2client.client import OAuth2Credentials

import json
import requests

from api.google_auth import create_google_oauth_flow, get_authenticated_service, get_user_info

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'


db = SQLAlchemy(app)
login_manager = LoginManager(app)
oauth = OAuth2Provider(app)



from oauth2client.client import OAuth2WebServerFlow

def create_google_oauth_flow(redirect_uri):
    flow = OAuth2WebServerFlow(
        client_id='YOUR_CLIENT_ID',
        client_secret='YOUR_CLIENT_SECRET',
        scope='openid email',
        redirect_uri=redirect_uri,
    )
    return flow
@app.route('/google/callback')
def google_callback():
    flow = create_google_oauth_flow('http://localhost/google/callback')
    credentials = flow.step2_exchange(request.args.get('code'))
    # Store the credentials securely, and use them to authenticate requests.
    # we store them in our database or another secure location.
    return 'OAuth2 Callback Successful'



def get_authenticated_service(credentials):
    if credentials and credentials.valid:
        return build('service_name', 'version', credentials=credentials)







# with open('config.json', 'r') as config_file:
#     config = json.load(config_file)

# app.config['GOOGLE_API_KEY'] = config['google_api_key']


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    tokens = db.relationship('OAuth2Token', backref='user', lazy=True)

class OAuth2Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255), unique=True, nullable=False)
# @app.route('/')
# def root():
#     return("LOL")
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    if user and pbkdf2_sha256.verify(password, user.password):
        login_user(user)
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/google/login')
def googleLogin():
    redirect_uri = 'http://localhost'
    flow = create_google_oauth_flow(redirect_uri)
    credentials = flow.run_local_server(port=0)
    authenticated_service = get_authenticated_service(credentials)
    user_info = get_user_info(authenticated_service)
    
    print("User's Google ID:", user_info.get('id'))
    print("User's Name:", user_info.get('name'))
    print("User's Email:", user_info.get('email'))

    return "User's Google ID: " + user_info.get('id') + "    User's Name:" + user_info.get('name') + "   User's Email:" + user_info.get('email')



 import requests

from api.google_auth import create_google_oauth_flow, get_authenticated_service, get_user_info
from api.google_auth import build_service_connection, create_google_oauth_flow, get_authenticated_service, get_user_info

app = Flask(__name__)
app = Flask(__name__,static_url_path='', 
            static_folder='web/static',
            template_folder='web/templates')
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
oauth = OAuth2Provider(app)
# login_manager = LoginManager(app)
# oauth = OAuth2Provider(app)
global google_credentials
google_credentials = None

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    tokens = db.relationship('OAuth2Token', backref='user', lazy=True)
# class User(UserMixin, db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     password = db.Column(db.String(120), nullable=False)
#     tokens = db.relationship('OAuth2Token', backref='user', lazy=True)

class OAuth2Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255), unique=True, nullable=False)
# class OAuth2Token(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
#     token_type = db.Column(db.String(40))
#     access_token = db.Column(db.String(255), unique=True, nullable=False)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
# @app.route('/login', methods=['POST'])
# def login():
#     data = request.json
#     username = data.get('username')
#     password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and pbkdf2_sha256.verify(password, user.password):
        login_user(user)
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401
#     user = User.query.filter_by(username=username).first()
#     if user and pbkdf2_sha256.verify(password, user.password):
#         login_user(user)
#         return jsonify({'message': 'Login successful'}), 200
#     else:
#         return jsonify({'error': 'Invalid credentials'}), 401

@app.route("/")
def index():
    return render_template("index.html")


@app.route('/google/login')
def googleLogin():
    redirect_uri = 'http://localhost'
    flow = create_google_oauth_flow(redirect_uri)
    credentials = flow.run_local_server(port=0)
    authenticated_service = get_authenticated_service(credentials)
    google_credentials = flow.run_local_server(port=0)
    authenticated_service = get_authenticated_service(google_credentials)
    user_info = get_user_info(authenticated_service)

    print("User's Google ID:", user_info.get('id'))
    print("User's Name:", user_info.get('name'))
    print("User's Email:", user_info.get('email'))

    return "User's Google ID: " + user_info.get('id') + "    User's Name:" + user_info.get('name') + "   User's Email:" + user_info.get('email')

@app.route('/query/<service_name>/version/<version_name>', methods=['POST'])
def query(service_name, version_name):
    redirect_uri = 'http://localhost'
    flow = create_google_oauth_flow(redirect_uri)
    # if google_credentials == None:
    google_credentials = flow.run_local_server(port=0)
    query_service = build_service_connection(service_name, version_name, google_credentials)
    if service_name == 'admin' and version_name == 'reports_v1':
        activities = query_service.activities().list(
            userKey='all',
            applicationName='drive',
            maxResults=10
        ).execute()
        # if 'items' in activities:
        #     for activity in activities['items']:

        return activities
    else:
        return 'UNKNOWN SERVICE'


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin_user = User.query.filter_by(username='admin').first()
        if(admin_user is None):
            admin_user = User(username='admin', password=pbkdf2_sha256.hash("333"))
            db.session.add(admin_user)
            db.session.commit()
    # with app.app_context():
    #     db.create_all()
    #     admin_user = User.query.filter_by(username='admin').first()
    #     if(admin_user is None):
    #         admin_user = User(username='admin', password=pbkdf2_sha256.hash("333"))
    #         db.session.add(admin_user)
    #         db.session.commit()
    app.run(debug=True)  


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin_user = User.query.filter_by(username='admin').first()
        if(admin_user is None):
            admin_user = User(username='admin', password=pbkdf2_sha256.hash("333"))
            db.session.add(admin_user)
            db.session.commit()


#here need to create app.app_context(): for the api data

# app.config['GOOGLE_API_KEY'] = 'google_api_key'
# @app.route('/fetch_google_drive_data')
# def fetch_google_drive_data():
#     google_api_key = app.config['GOOGLE_API_KEY']
#     url = f'https://www.googleapis.com/drive/v3/files?key={google_api_key}'

#     response = requests.get(url)
#     data = response.json()

#     return jsonify(data)

    #app.run(debug=True)


if __name__ == '__main__':
    app.run(debug=True)









   
