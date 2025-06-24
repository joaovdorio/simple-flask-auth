from flask import Flask
from models.user import User
from database import db

app = Flask(__name__)
app.config['SECRET_KEY'] = "yoursecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db.init_app(app)