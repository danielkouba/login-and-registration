from flask import Flask, redirect, request, render_template, flash, session
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'user_registration')
app.secret_key = "TheSecretLifeOfTheKeys"


EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
#Minimum 8 characters at least 1 Uppercase Alphabet, 1 Lowercase Alphabet and 1 Number:
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]+$')


@app.route('/', methods=["GET"])
def index():
	return render_template("index.html")

@app.route('/users/new', methods=["POST"])
def create():
	result = []

	session['first_name'] = request.form['first_name']
	session['last_name'] = request.form['last_name']
	session['email'] = request.form['email']
	session['password'] = request.form['password']
	session['passconf'] = request.form['passconf']

	if len(session['first_name']) < 2:
		result.append("First name must be greater than 2 characters")
	if not session['first_name'].isalpha():
		result.append( "First name cannot contain numbers or special characters")

	if len(session['last_name']) < 2:
		result.append("Last name must be greater than 2 characters")
	if not session['last_name'].isalpha():
		result.append( "Last name cannot contain numbers or special characters")

	if len(session['email']) < 2:
		result.append( "Email must be greater than 2 characters")
	if not EMAIL_REGEX.match(session['email']):
		result.append( "Email address is not valid")

	#Password Check
	if len(session['password']) < 8:
		result.append("Password must be at least 8 characters.")
	if not PASSWORD_REGEX.match(session['password']):
		result.append( "Password needs at least 1 Capital 1 Lowercase and 1 Number")
	if not session['password'] == session['passconf']:
		result.append("Passwords must match.")

	if len(result) == 0:
		password = session['password']
		pw_hash = bcrypt.generate_password_hash(password)
		query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name,:email,:password, NOW(), NOW())"
		data = {
			"first_name" : session['first_name'],
			"last_name" : session['last_name'],
			"email" : session['email'],
			"password" : pw_hash
		}
		mysql.query_db(query, data)
		session.pop('first_name')
		session.pop('last_name')
		session.pop('email')
		session.pop('password')
		session.pop('passconf')
		flash("Registered Successfully",'success')
		return render_template('success.html')
	else: 
		for message in result:
			flash(message,'error')
	return redirect('/')

@app.route('/users/login', methods=["POST"])
def login():
	email = request.form['email']
	password = request.form['password']
	query = "SELECT * FROM users WHERE email = :email LIMIT 1"
	data = { "email": email }
	user = mysql.query_db(query,data)
	if user:
		if bcrypt.check_password_hash(user[0]['password'], password):
			print "LOGIN SUCCESSFUL"
			flash("LOGIN SUCCESSFUL",'success')
			return render_template('success.html')
	else:
		print "LOGIN UNSUCCESSFUL"
		flash("LOGIN UNSUCCESSFUL",'error')
		return redirect('/')



app.run(debug=True)