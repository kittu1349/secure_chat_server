from flask import Flask, redirect, url_for, render_template, request, flash, session
# we use flask session to handle all login related functions instead of flask-login
# we use this to save information in a database
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
# hashing and salting the password
from flask_bcrypt import Bcrypt
import random
from string import digits, ascii_uppercase
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView

# to create secret key for session
def generate_secertkey():
    n = 16
    key = "".join(random.choices(ascii_uppercase + digits, k=n))
    return str(key)


app = Flask(__name__)
app.secret_key = generate_secertkey()
# users is name of table
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
# below, so we dont track all modifications
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# to expire the session after some time
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=20)

bcrypt = Bcrypt(app)

# to create a database
db = SQLAlchemy(app)

# table named user to store username and password
class Users(db.Model):
    id = db.Column("id", db.Integer, primary_key=True)
    username = db.Column("username", db.String(100), unique=True, nullable=False)
    password = db.Column("password", db.String(100), nullable=False)
    admin = db.Column("admin", db.Boolean, default=False)

# access only to logged in users and if they are admin
class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return "user" in session and session.get("admin")

    def inaccessible_callback(self, name, **kwargs):
        flash("You are not authorized to access this page!")
        return redirect(url_for("login"))

# below hides the password column on admin panel
class UserAdmin(ModelView):
    column_exclude_list = ('password',)
    form_excluded_columns = ('password',)

# creating admin with ability to be accessed only when logged in and hides password column
admin = Admin(app, index_view=MyAdminIndexView())
admin.add_view(UserAdmin(Users, db.session))

@app.route("/home")
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        # function that gets the nm value from the post request and creates a session cookie using that username
        username = request.form.get('username')
        password = request.form.get('password')
        found_user = Users.query.filter_by(username=username).first()
        if found_user and bcrypt.check_password_hash(found_user.password, password):
            session["user"] = username
            session["admin"] = found_user.admin
            # redirects to user dashboard
            flash("Login Successful!!")
            return redirect(url_for("dashboard"))
        else:
            # if username/password don't exist or are wrong
            flash("Invalid username or password.")
    if "user" in session:  # when /login, checks for session cookies, if present leads to dashboard, else to login page
        flash("Already Logged in!!")
        return redirect(url_for("dashboard"))
    return render_template("login.html")

# register section
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # checks if the username already exists
        if Users.query.filter_by(username=username).first():
            flash("Username already exists, please choose a different one.")
            return redirect(url_for('register'))
        # hashes the password and stores in database
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = Users(username=username, password=hashed_password)
        # add new user with username and hashed password to the db
        db.session.add(new_user)
        db.session.commit()
        flash("Registration Successful! Please log in.")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    if "user" in session:  # assigns the session cookie to the user dashboard
        username = session["user"]
        return render_template("dashboard.html", user=username)
    else:  # when /user, checks for session, else visits login
        flash("You are not logged in!!")
        return redirect(url_for("login"))

@app.route("/logout")
def logout():
    if "user" in session:  # assigns the session cookie to the user dashboard
        session.pop("user", None)
        session.pop("admin", None)
        flash("Logged out!!", "info")  # only flashes the message once after logout, not more than that
    else:
        # if already logged out
        flash("Already logged out!!")
    return redirect(url_for("login"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
