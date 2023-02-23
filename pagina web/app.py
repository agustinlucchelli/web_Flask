from flask import Flask, jsonify, render_template, make_response, request, session, redirect, url_for, g
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String
import datetime, secrets, sqlite3, bcrypt

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///C:/Users/User/Desktop/Python/PAGINA WEB/usuarios.db'
app.config["SALALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
    
@app.before_request
def before_request():
    
    g.user = current_user.is_authenticated
    
@app.context_processor
def inject_template_scope():
    injections = dict()

    def cookies_check():
        value = request.cookies.get('cookie_consent')
        return value == 'true'
    injections.update(cookies_check=cookies_check)

    return injections

# nos permite restringir rutas si no esta logeado, decorando la funcion de la ruta especifica a denegar el acceso.
def login_required(fun):
    
    @wraps(fun)
    def decorted_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return fun(*args, **kwargs)
    return decorted_function


class LOGIN_FORM(FlaskForm):
    
    username = StringField('username', validators = [DataRequired(), Length(min = 5, max = 25)])
    password = PasswordField('password', validators = [DataRequired()])
    submit = SubmitField('LogIn')
    
class REGISTER_FORM(FlaskForm):
    
    username = StringField('username', validators = [DataRequired(), Length(min = 5, max = 25)])
    password = PasswordField('password', validators = [DataRequired()])
    email = StringField('email', validators = [DataRequired(), Email()])
    submit = SubmitField('Register')
    
   
class Usuario(UserMixin, db.Model):
    
    id = Column(Integer, primary_key = True)
    password = Column(String(80))
    username = Column(String(80))
    email = Column(String(120))
    
    __table_args__ = (db.UniqueConstraint('password', 'username', 'email',name = '_password_username_email_uc'),)
    
    def __init__(self, username, email, password : str):
        
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    
    def __repr__(self):
        return f"<username = {self.username}, password = {self.password}, email = {self.email}>"

  
with app.app_context():
    db.create_all()
    
    
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

    
with app.app_context():
    
    db.create_all()

@app.route("/")
def index():    
    
    aceptar_cookies = request.cookies.get('aceptar_cookies')
    
    if aceptar_cookies == 'true':
        response = make_response(render_template('index.html', condicion=str(g.user)))
        response.set_cookie("aceptar_cookies", value="true", max_age=10000)
        response.set_cookie("nombre_de_la_cookie_", f"{request.remote_addr} - {datetime.datetime.now()}", max_age=10000)
        return response 
    else:
        
        try:
            
            # Si la cookie no existe, establece el valor por defecto como "false"
            response = make_response(render_template('no-cookie-index.html', rechazada = session["norechazada"]))
            response.set_cookie("aceptar_cookies", value="false", max_age=10000)
            return response
        
        except KeyError:
            
            session["norechazada"] = ""
            # Si la cookie no existe, establece el valor por defecto como "false"
            response = make_response(render_template('no-cookie-index.html', rechazada = True))
            response.set_cookie("aceptar_cookies", value="false", max_age=10000)
            return response
    

@app.route("/modificar", methods = ["POST"])
def modificar():
    
    data = request.get_json()
    valor = data['valor']

    session["norechazada"] = valor
    
    response = make_response(render_template("no-cookie-index.html", rechazada = session["norechazada"]))
    response.set_cookie("aceptar_cookies", value="false", max_age=10000)
    return response
    


@app.route("/sobre_nosotros")
def leer():
    
    nombre_de_la_cookie = request.cookies.get("nombre_de_la_cookie_")

    return render_template("sobre_nosotros.html", nombre_de_la_cookie = nombre_de_la_cookie)

@app.route("/daily_mails")
@login_required
def news():
    return render_template("daily_mails.html")

@app.route("/SingUp", methods = ["GET", "POST"])
def registro():
    
    form = REGISTER_FORM()
    
    if form.validate_on_submit() and request.method == "POST":

        username = form.username.data
        password = form.password.data
        email = form.email.data
        
        nuevo_usuario = Usuario(username = username, password = password, email = email)
            
        db.session.add(nuevo_usuario)
                
        try:
            db.session.commit()
        except:
            db.rollback()
        
        return redirect(url_for('index'))
    return render_template("registro.html", form = form)
    
@app.route("/LogOut")
def salir():
    
    logout_user()
    
    cookies = request.cookies
    
    response = make_response(redirect(url_for('index')))
    
    list(map(lambda cookie : response.delete_cookie(cookie), cookies))

    return response

@app.route("/login", methods = ["GET", "POST"])
def login():
    
    form = LOGIN_FORM()
    
    if form.validate_on_submit() and request.method == "POST":
        
        username = form.username.data
        password = form.password.data
        
        users = Usuario.query.filter_by(username = username).all()
        
        for i in users:
            
            try:
                password_ = bcrypt.checkpw(password.encode("utf-8"), i.password)
            except:
                return redirect(url_for("login"))
            
            if i is not None and password_:
                
                login_user(i)
                session['user_id'] = 1
                return redirect(url_for("index"))
                
    return render_template("login.html", form = form)

if __name__ == "__main__":
    
    app.run(debug = True)