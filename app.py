import os

from flask import Flask, redirect, render_template, request, session, flash, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from datetime import timedelta

from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin import Admin, AdminIndexView, expose

from dotenv import load_dotenv
from cryptography.fernet import Fernet

from helpers import login_required #, check_password_strength

load_dotenv()
# key = Fernet.generate_key()
# Pobranie klucza z pliku .env
secret_key_2 = os.getenv('SECRET_KEY_2')

if not secret_key_2:
    # Generowanie nowego klucza, jeśli nie istnieje i zapisanie go do .env
    secret_key_2 = Fernet.generate_key().decode()
    with open('.env', 'a') as f:
        f.write(f'\nSECRET_KEY_2={secret_key_2}')

cipher_suite = Fernet(secret_key_2.encode())

secret_key = os.urandom(24)


app = Flask(__name__)
csrf = CSRFProtect(app)

app.config['SECRET_KEY'] = secret_key

# WEBSITE_HOSTNAME exists only in production environment
if 'WEBSITE_HOSTNAME' not in os.environ:
    # local development, where we'll use environment variables
    print("Loading config.development and environment variables from .env file.")
    app.config.from_object('azureproject.development')
else:
    # production
    print("Loading config.production.")
    app.config.from_object('azureproject.production')


# configure the database 
app.config.update(
    SQLALCHEMY_DATABASE_URI = app.config.get('DATABASE_URI')
   
)

class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)

# initialize the db connection
db.init_app(app)

# import user model after db init
from models import User, Login, Role

with app.app_context():
    db.create_all()

# Enable Flask-Migrate commands "flask db init/migrate/upgrade" to work
migrate = Migrate(app, db)


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
app.config['SESSION_KEY_PREFIX'] = 'pm_' 
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=10)
Session(app)

class AdminModelView(ModelView):
    def is_accessible(self):
        # Sprawdź, czy sesja zawiera informacje o zalogowanym użytkowniku i jego roli
        if 'user_id' in session:
            user_id = session['user_id']
            user = User.query.get(user_id)
            if user and user.role.name == 'Admin':
                return True
        return False

    def inaccessible_callback(self, name, **kwargs):
        # Jeśli użytkownik nie ma dostępu, przekieruj go gdziekolwiek chcesz
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('login'))

admin = Admin(app, name='My Admin Panel', template_mode='bootstrap4', index_view=AdminIndexView(name='Home'))
admin.add_view(AdminModelView(User, db.session))
admin.add_view(AdminModelView(Role, db.session))
admin.add_view(AdminModelView(Login, db.session))


@app.before_request
def clear_session():
    if request.is_secure and request.path != '/login':
        session.clear()


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/view")
@login_required
def view():
        
        user = session.get("user_id")
        if not user:
            return redirect('/login')
    
        values = db.session.execute(db.select(User).where(User.user_id == user)).scalar()
        print(values)
        return render_template("view.html", values=values)

@app.route("/manager")
@login_required
def manager():
    
    user = session.get("user_id")
    if not user:
        return redirect('/login')

    logins = Login.query.filter_by(user_id=user).all()
    decrypted_logins = []
    for login in logins:
        decrypted_password = cipher_suite.decrypt(login.login_password).decode()
        decrypted_logins.append({
            'portal_name': login.portal_name,
            'login_name': login.login_name,
            'login_password': decrypted_password,
            'login_id': login.login_id
        })
    return render_template('manager.html', values=decrypted_logins)

@app.route("/updatepass/<int:login_id>", methods=["GET", "POST"])
@login_required
def updatepass(login_id):
        
        password_to_update = db.session.execute(db.select(Login).where(Login.login_id == login_id)).scalar()

        if not password_to_update:
            flash("Password not exist", "info")
            return render_template("manager.html")
        
        decrypted_password = cipher_suite.decrypt(password_to_update.login_password).decode()
        password_to_update.login_password = decrypted_password
        
        if request.method == "POST":
            # Ensure portal name was submitted
            if not request.form.get("portal_name"):
                flash("must provide portalname", "info")
                return render_template("updatepass.html")
        
            # Ensure login was submitted
            elif not request.form.get("login_name"):
                flash("must provide password", "info")
                return render_template("updatepass.html")

        # Ensure password was submitted
            elif not request.form.get("login_password"):
                flash("must provide password", "info")
                return render_template("updatepass.html")

            portal_name = request.form.get("portal_name")
            login_name = request.form.get("login_name")
            login_password = request.form.get("login_password")
            login_password_bytes = bytes(login_password, 'utf-8')
            cipher_text = cipher_suite.encrypt(login_password_bytes)
            
            # UPDATE password in database
            password_to_update.portal_name = portal_name
            password_to_update.login_name = login_name
            password_to_update.login_password = cipher_text
            
            try:
                db.session.commit()
                flash("Update Successful!")
                return redirect("/manager")
            except:
                db.session.rollback()
                flash("Problem with database, try again later")
                return render_template("updatepass.html", password_to_update = password_to_update)
        else:
            return render_template("updatepass.html", password_to_update = password_to_update)  

@app.route("/delete_password/<int:login_id>")
@login_required
def delete_password(login_id):
        
        password_to_delete = db.session.execute(db.select(Login).where(Login.login_id == login_id)).scalar()
       
        if not password_to_delete:
            flash("Password not exist", "info")
            return render_template("manager.html")
        try:
            db.session.delete(password_to_delete)
            db.session.commit()
            flash("Delete completed!")
            return redirect("/manager")
        except:
            flash("Problem with database try again later")
            return render_template("manager.html")


@app.route("/add", methods=["POST", "GET"])
@login_required
def add():
        
    if request.method == "POST":
        # Ensure portal name was submitted
        if not request.form.get("portal_name"):
            flash("must provide portalname", "info")
            return render_template("add.html")
        
        # Ensure login was submitted
        elif not request.form.get("login_name"):
            flash("must provide password", "info")
            return render_template("add.html")

        # Ensure password was submitted
        elif not request.form.get("login_password"):
            flash("must provide password", "info")
            return render_template("add.html")
        
        # Add password to database
        portal_name = request.form.get("portal_name")
        login_name = request.form.get("login_name")
        user_id = session.get("user_id")
        login_password = request.form.get("login_password")
        login_password_bytes = bytes(login_password, 'utf-8')
        cipher_text = cipher_suite.encrypt(login_password_bytes)
        new_password = Login(user_id = user_id, portal_name = portal_name, login_name = login_name, login_password = cipher_text)
        db.session.add(new_password)
        db.session.commit()

        # Redirect user home
        flash("New Password added succesful!", "info")
        return redirect("/manager")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("add.html")



@app.route("/register", methods=["POST", "GET"])
def register():

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("must provide username", "info")
            return render_template("register.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("must provide password", "info")
            return render_template("register.html")

        # Query database for username
        user = request.form.get("username")
        found_user = db.session.execute(db.select(User).where(User.name == user)).scalar()

        # Ensure username not exists
        if found_user:
            flash("User already exist", "info")
            return render_template("register.html")

        # Add user to database
        user = request.form.get("username")
        user_log = user
        hash = generate_password_hash(request.form.get("password"))
        user = User(name = user, password = hash, email = None)
        role = Role(name = 'User', user = user)
        db.session.add(user, hash)
        db.session.add(role)
        db.session.commit()

        # Login user
        found_user = db.session.execute(db.select(User).where(User.name == user_log)).scalar()
        session["user_id"] = found_user.user_id

        # Redirect user home
        flash("Register succesful!", "info")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/login", methods=["POST","GET"])
def login():
    
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Please provide username!", "info")
            return render_template("login.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Please provide password!", "info")
            return render_template("login.html")

        # Query database for username
        user = request.form.get("username")
        found_user =  db.session.execute(db.select(User).where(User.name == user)).scalar()

        # Ensure username exists and password is correct
        if not found_user or not check_password_hash(
            found_user.password, request.form.get("password")
        ):
            flash("User not exist or wrong password!", "info")
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = found_user.user_id

        # Redirect user to home page
        flash("Logged in!", "info")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/update/<int:id>", methods=["GET", "POST"])
@login_required
def update(id):
    user_to_update = db.session.execute(db.select(User).where(User.user_id == id)).scalar()
    
    if request.method == "POST":
        name = request.form.get('name')
        email = request.form.get('email')

        existing_user = db.session.execute(db.select(User).where(User.name == name, User.user_id != id)).scalar()
        
        if existing_user:
            flash("Username already exists. Please choose a different name.", "error")
            return render_template("update.html", user_to_update=user_to_update)
        
        existing_user_by_email = db.session.execute(db.select(User).where(User.email == email, User.user_id != id)).scalar()
        
        if existing_user_by_email:
            flash("Email already exists. Please choose a different email.", "error")
            return render_template("update.html", user_to_update=user_to_update)
        
        if user_to_update:
        
            user_to_update.name = name
            user_to_update.email = email
            
            try:
                db.session.commit()
                flash("Update Successful!")
                return redirect("/view")
            except:
                db.session.rollback()
                flash("Problem with database, try again later")
                return render_template("update.html", user_to_update = user_to_update)
    else:
        return render_template("update.html", user_to_update = user_to_update)    


@app.route("/delete/<int:id>")
@login_required
def delete(id):
        
        user_to_delete = db.session.execute(db.select(User).where(User.user_id == id)).scalar()
       
        if not user_to_delete:
            flash("User not exist", "info")
            return render_template("view.html")
        try:
            db.session.delete(user_to_delete)
            db.session.commit()
            session.clear()
            flash("Delete completed!")
            return redirect("/view")
        except:
            flash("Problem with database try again later")
            return render_template("view.html")


@app.route("/logout")
@login_required
def logout():
    
    flash("logged out! ", "info")
    session.clear()
    return redirect("/login")

if  __name__ == "__main__":
    app.run(debug=True)