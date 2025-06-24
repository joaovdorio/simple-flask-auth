from database import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    #id (int), username (text), password (text)
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(0), nullable=False)