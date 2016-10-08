from flask import Flask, redirect, render_template, request, session, flash
from mysqlconnection import MySQLConnector
import re
from flask.ext.bcrypt import Bcrypt


app = Flask(__name__)
app.secret_key = "ShhhSneaky"
mysql = MySQLConnector(app, 'registration')
bcrypt = Bcrypt(app)

#regex matches
allLetters_REGEX = re.compile(r'^[a-zA-Z]')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')


@app.route('/')
def index():

    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register_user():
    d = request.form
    if not allLetters_REGEX.match(d['first_name']):
        flash('Names must only be Letters', 'error')
        return redirect('/')
    elif not allLetters_REGEX.match(d['last_name']):
        flash('Names must only be Letters', 'error')
        return redirect('/')
    elif len(d['first_name']) <2 or len(d['last_name']) < 2:
        flash('Names must be more than 2 characters per field', 'error')
        return redirect('/')
    elif not EMAIL_REGEX.match(d['email']):
        flash('Email is not in the correct format', 'error')
        return redirect('/')
    elif len(d['password']) < 8:
        flash('Password must be 8 characters or more', 'error')
        return redirect('/')
    elif d['password'] != d['password_confirm']:
        flash('Passwords do not match', 'error')
        return redirect('/')

    print ('Validation Checks Passed')
    #Build insert
    pw_hash = bcrypt.generate_password_hash(d['password'])
    print ('Password Encrypted & Hashed')

    insertQuery = 'INSERT INTO users (first_name, last_name, email, password, created_at) VALUES (:first_name, :last_name, :email, :pw_hash, NOW())'
    data = {
        'first_name': d['first_name'],
        'last_name': d['last_name'],
        'email': d['email'],
        'pw_hash': pw_hash
    }

    mysql.query_db(insertQuery, data)
    print ('Data Submitted to Database')
    return render_template('success.html', hidelogin = 'hidden', hideregister = '')

@app.route('/login', methods=['POST'])
def login():
    d = request.form
    loginQuery = 'SELECT * FROM users WHERE email = :email LIMIT 1'
    data = {
        'email': d['email']
    }
    user = mysql.query_db(loginQuery, data)
    if bcrypt.check_password_hash(user[0]['password'], d['password']):
        #login the user

        session['user_id'] = user[0]['id']
        return render_template('success.html', hidelogin = '', hideregister = 'hidden')
    else:
        flash('Email or Password does not match existing user.  Please Try again or Register', 'error')
        return redirect('/')


app.run(debug=True)
