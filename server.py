
# ? Importing all the technologies and libraries needed
from flask import Flask, request, redirect, flash, session, render_template
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re

# ? Initializing all the constants we need for the project
app = Flask(__name__)
app.secret_key = 'damascusXIII'
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

# ? Render the login and registration page
@app.route('/')
def login_registration():
    if 'login' not in session:
        session['login'] = False
    return render_template('index.html')

# ? Render the dashboard for the user
@app.route('/magazines')
def dashboard():
    if not session['login']:
        return redirect('/')
    else:
        magazines = connectToMySQL('subscriptions').query_db("SELECT * FROM magazines;")
        users = connectToMySQL('subscriptions').query_db("SELECT * FROM users;")
        return render_template('dashboard.html', mags=magazines, users_tp=users)

# ? Render the magazine page to view the magazine
@app.route('/magazines/<magazine_id>')
def magazine(magazine_id):
    if not session['login']:
        return redirect('/')
    else:
        data = {
            'magazine_id': magazine_id
        }
        users_db = connectToMySQL('subscriptions').query_db("SELECT * FROM users;")
        magazine_db = connectToMySQL('subscriptions').query_db("SELECT * FROM magazines WHERE magazines.id=%(magazine_id)s",data)
        subscribers_db = connectToMySQL('subscriptions').query_db("SELECT * FROM subscriptions WHERE subscriptions.magazine_id=%(magazine_id)s",data)
        return render_template('magazine.html', magazine_tp=magazine_db, subscribers_tp=subscribers_db, users_tp=users_db)

# ? Render the page for the user to write a new magazine
@app.route('/magazines/new')
def new_magazine():
    if not session['login']:
        return redirect('/')
    else:
        return render_template('new_magazine.html')

# ? Render the page to view the users account page and edit their account information
@app.route('/users/<user_id>')
def account(user_id):
    if not session['login']:
        return redirect('/')
    else:
        data = {
            'user_id': user_id
        }
        user_db = connectToMySQL('subscriptions').query_db("SELECT * FROM users WHERE id=%(user_id)s",data)
        magazines_db = connectToMySQL('subscriptions').query_db("SELECT * FROM magazines WHERE author_id=%(user_id)s;",data)
        count_db = connectToMySQL('subscriptions').query_db("SELECT COUNT(*) as subscribers, magazine_id FROM subscriptions GROUP BY magazine_id;")
        return render_template('account.html', user_tp=user_db, magazines_tp=magazines_db, count_tp=count_db)

# * Updates a users account information
@app.route('/users/<user_id>/update', methods=['POST'])
def update_account(user_id):
    # validate the updated names and email
    is_valid = True
    if len(request.form['f_name']) < 2:
        is_valid = False
        flash('* First name must be at least 2 characters long', 'vp_first')
    if len(request.form['l_name']) < 2:
        is_valid = False
        flash('* Last name must be at least 2 characters long', 'vp_last')
    if not EMAIL_REGEX.match(request.form['email']):
        is_valid = False
        flash('* Please enter a valid email address', 'vp_email')

    if not is_valid: # is not valid redirect to the page of the account
        return redirect('/users/'+user_id)
    else:   # make sure the email is unique
        is_taken = False

        data = {
            'user_id': user_id
        }
        user_db = connectToMySQL('subscriptions').query_db("SELECT * FROM users WHERE id=%(user_id)s",data)
        users = connectToMySQL('subscriptions').query_db("SELECT email FROM users;")
        for user in users:
            if user['email'] == request.form['email'] and request.form['email']!=user_db[0]['email']:
                is_taken = True
                flash('* Enter a different email, that is taken', 't_email')

        if is_taken:    # if email is taken redirect to the account page
            return redirect('/users/'+user_id)
        else:   # if it is not taken we are gonna update the account information
            data = {
                'user_id': user_id,
                'first_name': request.form['f_name'],
                'last_name': request.form['l_name'],
                'email': request.form['email']
            }
            # update the database with the new information
            connectToMySQL('subscriptions').query_db('UPDATE users SET first_name=%(first_name)s,last_name=%(last_name)s,email=%(email)s,updated_at=NOW() WHERE id=%(user_id)s',data)
            return redirect('/users/'+user_id)

# * Subscribes a user to the selected magazine
@app.route('/magazines/subscribe/<user_id>/<magazine_id>')
def subscribe(user_id,magazine_id):
    if not session['login']:
        return redirect('/')
    else:
        subscribed = False
        subscribers = connectToMySQL('subscriptions').query_db("SELECT * FROM subscriptions;")
        for subscriber in subscribers:
            if subscriber['user_id']==int(user_id) and subscriber['magazine_id']==int(magazine_id):
                subscribed = True
                break

        if subscribed:
            return redirect('/magazines')
        else:
            data = {
                'user_id': user_id,
                'magazine_id': magazine_id
            }
            connectToMySQL('subscriptions').query_db("INSERT INTO subscriptions(user_id,magazine_id) VALUES(%(user_id)s,%(magazine_id)s);",data)
            return redirect('/magazines')

# * Create a new magazine entry
@app.route('/magazines/create', methods=['POST'])
def create_magazine():
    #validating the new magazine
    is_valid = True
    if len(request.form['title']) < 2:
        is_valid = False
        flash('* Title should be at least 2 characters long', 'vm_title')
    if len(request.form['description']) < 10:
        is_valid = False
        flash('* Description should be at least 10 characters long', 'vm_description')

    if not is_valid:    # if the title and descripition is not valid, redirect back to the add magazine page
        return redirect('/magazines/new')
    else:
        data = {
            'author_id': session['user_id'],
            'title': request.form['title'],
            'content': request.form['description']
        }
        connectToMySQL('subscriptions').query_db("INSERT INTO magazines(author_id,title,content) VALUES(%(author_id)s,%(title)s,%(content)s);",data)
        return redirect('/magazines')

# * Deletes a magazine entry
@app.route('/users/<user_id>/delete/<magazine_id>')
def delete_magazine(user_id,magazine_id):
    if not session['login']:
        return redirect('/')
    else:
        data = {
            'magazine_id': magazine_id
        }
        connectToMySQL('subscriptions').query_db("DELETE FROM subscriptions WHERE magazine_id=%(magazine_id)s",data)
        connectToMySQL('subscriptions').query_db("DELETE FROM magazines WHERE magazines.id=%(magazine_id)s",data)
        return redirect('/users/'+user_id)

# * Clear the user_id after the user logs out
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# * Validate the user login attempt - redirect to the dashboard page if approved
@app.route('/login', methods=['POST'])
def login():
    # validating the login attempt
    is_valid = True
    if not EMAIL_REGEX.match(request.form['email']):
        is_valid = False
        flash('* Enter a valid email address', 'vl_email')
    if len(request.form['password'])<8:
        is_valid = False
        flash('* Password must be greater than 8 characters long', 'vl_password')

    if not is_valid:    # if not valid redirecting to the home page for the user to try again
        return redirect('/')
    else:   #otherwise we will check whether the email can be found in our database
        is_user = False
        users = connectToMySQL('subscriptions').query_db("SELECT * FROM users;")

        for user in users:
            if user['email'] == request.form['email']:
                is_user = True
                check_user = user['email']
                break
        
        if not is_user: # is the email entered cannot be found then flash this message and redirect to the home page
            flash('* That account does not exist', 'fl_email')
            return redirect('/')
        else:   #otherwise we will now check the password to see if it is matching the username entered
            for user in users:
                if user['email'] == check_user:
                    if bcrypt.check_password_hash(user['password'],request.form['password']):
                        session['user_id'] = user['id']
                        session['login'] = True
                        return redirect('/magazines')

            flash('* Incorrect password try again', 'fl_password') # if it exits the loop it means no password was found with that entered password
            return redirect('/')

# * Validate, or submit the account information - dependant on the users submission
@app.route('/signup', methods=['POST'])
def signup():
    # validating the creation attempt
    is_valid = True
    if request.form['f_name'].isalpha()==False or len(request.form['f_name'])<2:
        is_valid = False
        flash('* First name must be at least 2 character and nothing but letters', 'vc_first')
    if request.form['l_name'].isalpha()==False or len(request.form['l_name'])<2:
        is_valid = False
        flash('* Last name must be at least 2 character and nothing but letters', 'vc_last')
    if not EMAIL_REGEX.match(request.form['email']):
        is_valid = False
        flash('* Enter a valid email address', 'vc_email')
    if len(request.form['password'])<8 or len(request.form['password'])>30:
        is_valid = False
        flash('* Password must be between 8 and 30 characters long', 'vc_password')
    if request.form['password'] != request.form['c_password']:
        is_valid = False
        flash('* Password doesn\'t match', 'vc_c_password')

    if not is_valid:    # if not valid redirecting to the home page for the user to try again
        return redirect('/')
    else:   # otherwise we will check if the input is unique now
        is_unique = True
        users = connectToMySQL('subscriptions').query_db('SELECT * FROM users;')
        
        for email in users: # check if the email is unique
            if email['email'] == request.form['email']:
                is_unique = False
                flash('* Email is taken', 'uc_email')
                break
        
        if not is_unique:   # if not unique redirecting to the home for the user to try again
            return redirect('/')
        else:               # if all checks are complete now it will insert the data into the table
            data = {
                'f_name': request.form['f_name'],
                'l_name': request.form['l_name'],
                'email': request.form['email'],
                'password': bcrypt.generate_password_hash(request.form['password'])
            }
            query = "INSERT INTO users(first_name,last_name,email,password) VALUES(%(f_name)s,%(l_name)s,%(email)s,%(password)s);"  # enter the information of the user in order and formated to enter the database
            query = connectToMySQL('subscriptions').query_db(query,data)
            return redirect('/')    # redirect to the login page for the user to login to their account

# ? Turns debug mode on for the browser while working on the website
if __name__ == '__main__':
    app.run(debug=True)