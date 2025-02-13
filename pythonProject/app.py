from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from flask_wtf import FlaskForm
import bcrypt
from wtforms import ValidationError
from wtforms.fields.simple import SubmitField, StringField, PasswordField
from wtforms.validators import DataRequired, Email
from authlib.integrations.flask_client import OAuth
import requests
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = Flask(__name__)

# App Configuration
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "ALongRandomlyGeneratedString")
app.config['MYSQL_HOST'] = os.getenv("MYSQL_HOST", "localhost")
app.config['MYSQL_USER'] = os.getenv("MYSQL_USER", "root")
app.config['MYSQL_PASSWORD'] = os.getenv("MYSQL_PASSWORD", "")
app.config['MYSQL_DB'] = os.getenv("MYSQL_DB", "flask_users")

mysql = MySQL(app)

# Google OAuth Configuration
oauth = OAuth(app)

oauth.register(
    "google",
    client_id=os.getenv("OAUTH2_CLIENT_ID"),
    client_secret=os.getenv("OAUTH2_CLIENT_SECRET"),
    client_kwargs={"scope": "openid email profile"},
    server_metadata_url=os.getenv("OAUTH2_META_URL"),
)

# WTForms for Registration & Login
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM table_users WHERE email = %s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError("Email already taken")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


# Routes
@app.route('/')
def home():
    return render_template("base.html")


# Signup with Email
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cursor = mysql.connection.cursor()
        cursor.execute('INSERT INTO table_users(name, email, password) VALUES (%s, %s, %s)',
                       (name, email, hashed_password))
        mysql.connection.commit()
        cursor.close()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template("signup.html", form=form)


# Login with Email
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute('SELECT id, name, email, password FROM table_users WHERE email = %s', (email,))
        user = cursor.fetchone()
        cursor.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['id'] = user[0]
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password.", "danger")

    return render_template("login.html", form=form)


# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'id' in session:
        id = session['id']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM table_users WHERE id=%s", (id,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            return render_template('dashboard.html', user=user)

    flash("Please log in first.", "warning")
    return redirect(url_for('home'))


# Logout
@app.route('/logout')
def logout():
    session.pop('id', None)
    flash("You have been logged out successfully", "info")
    return redirect(url_for('home'))


# Google Signup
@app.route("/signup-google")
def googleSignup():
    return oauth.google.authorize_redirect(redirect_uri=url_for("googleSignupCallback", _external=True))


@app.route("/signup-google/callback")
def googleSignupCallback():
    token = oauth.google.authorize_access_token()
    userinfo = requests.get("https://www.googleapis.com/oauth2/v2/userinfo",
                            headers={"Authorization": f"Bearer {token['access_token']}"}).json()

    email = userinfo.get("email")
    name = userinfo.get("name")

    if not email:
        flash("Google authentication failed. Please try again.", "danger")
        return redirect(url_for("signup"))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id FROM table_users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user:
        flash("This email is already registered. Please log in.", "warning")
        cursor.close()
        return redirect(url_for("login"))

    cursor.execute("INSERT INTO table_users (name, email, password) VALUES (%s, %s, %s)", (name, email, ""))
    mysql.connection.commit()
    user_id = cursor.lastrowid
    cursor.close()

    session["id"] = user_id
    flash("Signup successful! You are now logged in.", "success")
    return redirect(url_for("dashboard"))


# Google Login
@app.route("/login-google")
def googleLogin():
    return oauth.google.authorize_redirect(redirect_uri=url_for("googleLoginCallback", _external=True))


@app.route("/login-google/callback")
def googleLoginCallback():
    token = oauth.google.authorize_access_token()
    userinfo = requests.get("https://www.googleapis.com/oauth2/v2/userinfo",
                            headers={"Authorization": f"Bearer {token['access_token']}"}).json()

    email = userinfo.get("email")

    if not email:
        flash("Google authentication failed. Please try again.", "danger")
        return redirect(url_for("login"))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id FROM table_users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash("No account found. Please sign up with Google first.", "warning")
        return redirect(url_for("signup"))

    session["id"] = user[0]
    flash("Login successful!", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
