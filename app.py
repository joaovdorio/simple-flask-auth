#importação

from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__) #define o nome da aplicação
app.config['SECRET_KEY'] = "your_secret_key" #secret key da aplicação
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:admin123@127.0.0.1:3306/flask-crud' #endereço do banco de dados
#invoke mysql and pymysql to run through docker
#ip: localhost, port: 3306, flask-crud: we define that

login_manager = LoginManager()
#used from flask_login

db.init_app(app)
#initiating the app utilizing SQLAlchemy

login_manager.init_app(app)
#initiating the app utilizing LoginManager

login_manager.login_view = 'login'
#view login

@login_manager.user_loader #endpoint for loading the user
def load_user(user_id): #creating function using user_id as instance
    return User.query.get(user_id) #search into the database for the user_id

@app.route('/login', methods=['POST']) #endpoint for loging in

def login():
    #creating the function login, getting the data we insert in the postman and authenticate using the database.
    #the usernames are unique, so we can order by the first result it returns to us.
    #also, using bcrypt to validate the password we encoded before.
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        # Login
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)): 
            #bcrypt: checkpw verifies the password entered now with the password in the database, which has already been hashed
            #because it has already been hashed by bcrypt itself, theres no risk of getting it wrong.
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message":"Login realizado com sucesso"}), 200
            
    return jsonify({"message":"As credenciais estão inválidas"}), 400

@app.route('/logout', methods=["GET"]) #endpoint for logging out
#logging out method - we define here using "login_required" so the user must be logged in the app to log out.
@login_required
def logout(): #noting too sketchy, just using a function from flask-login
    logout_user()
    return jsonify({"message" : "Logout realizado com sucesso"}) #no return codes here, 200 is the default value for this

##login and logout are functions from the flask-login

@app.route('/user', methods=['POST']) #endpoint for creating user
def create_user():
    #creating the function create_user, getting the data we insert in the postman and pushing into the database.
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    #Cadastro
    if username and password: #validating if both infos were inserted by user
        
        password_hashed = bcrypt.hashpw(str.encode(password), bcrypt.gensalt()) #var used for encrypting the password using bcrypt, gensalt is used to put random entries
        #Sal é um dado aleatório que é usado como entrada adicional pra uma função unidirecional que quebra os dados.
        #Aqui dentro do gensalt voce pode decidir quantas rodadas de salt vão ser colocadas dentro do password
        #Por padrão, são utilizadas 12.

        user = User(username=username, password=password_hashed, role='user') #here, we define which information we want to push into the database. 
        #IMPORTANT: the default value of role is 'user', but we can put as a admin if we want. in this case, we declare it for educational
        #purposes only.

        db.session.add(user) #push the info for the database
        db.session.commit() #validates and effects the requisition

        return jsonify({"message":"Cadastro realizado com sucesso"}), 200
        
    
    return jsonify({"message":"Houveram inconsistências no seu cadastro. Verifique e tente novamente"}), 401

@app.route('/user/<int:id_user>', methods=["GET"]) #endpoint to view user's username
@login_required #you must be logged in to access this endpoint
def read_user(id_user): #function created to read the user's username

    user = User.query.get(id_user) #search into the database for the username attached to the user_id logged in

    #first we verify if there's a user_id. if yes, we get the username back. if not, error message 404.
    if user:
        return {"username": user.username} 
    return jsonify({"message":"Usuário não encontrado"}), 404


@app.route('/user/<int:id_user>', methods=["PUT"]) #enfpoint for updating the user.
#Was a little confused with the logic here, but after it was built, it was less scary.

@login_required ##you must be logged in to access this endpoint
def update_user(id_user):
    data = request.json
    #getting the data we insert in the postman

    user = User.query.get(id_user)
    #search into the database for the user logged in and setting the user var as the id_user

    if id_user != current_user.id and current_user.role == 'user':
        return jsonify({"message":"Permissão negada"}), 403
    #here we verify if the user logged in is different as the user we wanna update.
    #besides that, if the user is not an admin, we wont let him update any info
    #i truly believe people should change their passwords, but its just a study case.

    if user:
        user.password = data.get("password")
    #so, if the validations are different from the ones above, we let them change their passwords.
    #again, we define which information we want to push into the database. 

        db.session.add(user) #push the info for the database
        db.session.commit() #validates and effects the requisition
        
        return jsonify({"message":f"Usuário {id_user} atualizado com sucesso"}), 200

    return jsonify({"message":"Usuário não encontrado"}), 404

@app.route('/user/<int:id_user>', methods=["DELETE"]) #endpoint for deleting user.
@login_required #you must be logged in to access this endpoint

def delete_user(id_user): #creating a funcion to delete the user. only the admin can delete the users, but he cant delete his own user

    user = User.query.get(id_user)
    #search into the database for the user logged in and setting the user var as the id_user

    if id_user == current_user.id:
       return jsonify({"message":"Não é possível apagar seu próprio usuário"}), 403
    #the user cant delete his own user, not even a admin
    
    if current_user.role != 'admin':
        return jsonify({"message":"Operação não permitida"}), 403
    #the normal role cant delete any users, only admins

    if user and id_user != current_user.id:
    #if theres a login session going on, and the user != current user, he can do it

        db.session.delete(user) #push the info to the database (in this case, the deletion)
        db.session.commit() #validates and effects the requisition

        return jsonify({"message":f"Usuário {id_user} deletado com sucesso"}), 200
    
    
    return jsonify({"message":"Usuário não encontrado"}), 404

#prevent the app from running automatically (as a import for example)
if __name__ == '__main__':
    app.run(debug=True)