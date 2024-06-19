from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
from dotenv import load_dotenv
import psycopg2

load_dotenv()

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

database_url = os.getenv('DATABASE_URL')

conn = psycopg2.connect(database_url)


conn = psycopg2.connect(
    dbname="mydatabase",
    user="myuser",
    password="mypassword",
    host="/tmp"
)

@app.route('/register', methods=['POST'])
def register():
    pass  # Placeholder for future code
    # Your registration logic here

@app.route('/login', methods=['POST'])
def login():
    pass  # Placeholder for future code
    # Your login logic here

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    pass  # Placeholder for future code
    # Your profile logic here




# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     password = db.Column(db.String(120), nullable=False)
#

# @app.route('/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
#     new_user = User(username=data['username'], password=hashed_password)
#     db.session.add(new_user)
#     db.session.commit()
#     return jsonify({'message': 'User created successfully'}), 201
#

# @app.route('/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     user = User.query.filter_by(username=data['username']).first()
#     if user and bcrypt.check_password_hash(user.password, data['password']):
#         access_token = create_access_token(identity={'username': user.username})
#         return jsonify(access_token=access_token), 200
#     return jsonify({'message': 'Invalid credentials'}), 401
#

# @app.route('/profile', methods=['GET'])
# @jwt_required()
# def profile():
#     current_user = get_jwt_identity()
#     return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    app.run(debug=True)
