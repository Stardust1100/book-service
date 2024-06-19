from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
import os
from dotenv import load_dotenv
import psycopg2

load_dotenv()

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# Connect to PostgreSQL database
conn = psycopg2.connect(
    dbname=os.getenv('DB_NAME'),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD'),
    host=os.getenv('DB_HOST')
)


cursor = conn.cursor()

# Create users table if it doesn't exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    password VARCHAR(120) NOT NULL
)
""")
conn.commit()

from flask_jwt_extended import get_jwt

@app.route('/user', methods=['GET'])
@jwt_required()
def new_route():
    jwt = get_jwt()
    if jwt:
        current_user = get_jwt_identity()
        return jsonify({'message': 'This is a home route', 'logged_in_as': current_user}), 200
    else:
        return jsonify({'message': 'This is a home route', 'status': 'Not logged in'}), 200

@app.route('/register', methods=['POST'])
@jwt_required()
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (data['username'], hashed_password))
        conn.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'message': str(e)}), 400

@app.route('/login', methods=['POST'])
@jwt_required()
def login():
    data = request.get_json()
    cursor.execute("SELECT * FROM users WHERE username = %s", (data['username'],))
    user = cursor.fetchone()
    if user and bcrypt.check_password_hash(user[2], data['password']):
        access_token = create_access_token(identity={'username': user[1]})
        return jsonify(access_token=access_token), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200



class User:
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

def create_user(username, password):
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
    conn.commit()


def get_user(username):
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user_row = cursor.fetchone()
    if user_row:
        return User(id=user_row[0], username=user_row[1], password=user_row[2])
    else:
        return None





if __name__ == '__main__':
    app.run(debug=True)
