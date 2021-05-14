from flask import Flask, render_template, request, flash, redirect, url_for, session, logging, jsonify, Response
from flask_mysqldb import MySQL
from wtforms import Form, StringField, PasswordField, TextAreaField, IntegerField, validators
from wtforms.validators import DataRequired
from passlib.hash import sha256_crypt
from functools import wraps
import timeago
import datetime
from wtforms.fields.html5 import EmailField
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail, Message

app = Flask(__name__, static_url_path='/static')
app.config.from_pyfile('config.py')

mysql = MySQL(app)
mail = Mail(app)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        category = request.form['category']
        # Create cursor
        cur = mysql.connection.cursor()

        if category == "All":
            result = cur.execute("SELECT * FROM blogs")
        else:
            result = cur.execute(
                f"SELECT * FROM blogs WHERE category = \"{category}\"")
        if result > 0:
            blogs = cur.fetchall()
            for blog in blogs:
                blog['date'] = blog['date'].strftime('%d %B, %Y')
            return render_template('blogs.html', blogs=blogs)
        else:
            msg = f"No Blogs Found For {category}"
            return render_template('blogs.html', result=result, msg=msg)
        # Close connection
        cur.close()
    else:
        # Create cursor
        cur = mysql.connection.cursor()

        # Get latest blogs
        result = cur.execute("SELECT * FROM blogs ORDER BY date DESC")

        if result > 0:
            blogs = cur.fetchall()
            for blog in blogs:
                blog['date'] = blog['date'].strftime('%d %B, %Y')
            return render_template('blogs.html', blogs=blogs)
        else:
            flash('No Blogs Found', 'success')
            return redirect(url_for('addBlogs'))
        # Close connection
        cur.close()
    return render_template('blogs.html')


class SignUpForm(Form):
    first_name = StringField('First Name', [validators.Length(min=1, max=100)])
    last_name = StringField('Last Name', [validators.Length(min=1, max=100)])
    email = EmailField('Email address', [
                       validators.DataRequired(), validators.Email()])
    username = StringField('Username', [validators.Length(min=4, max=100)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'logged_in' in session and session['logged_in'] == True:
        flash('You are already logged in', 'info')
        return redirect(url_for('addBlogs'))
    form = SignUpForm(request.form)
    if request.method == 'POST' and form.validate():
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE email=%s", [email])
        if result > 0:
            flash('The entered email address has already been taken.Please try using or creating another one.', 'info')
            return redirect(url_for('signup'))
        else:
            cur.execute("INSERT INTO users(first_name, last_name, email, username, password) VALUES(%s, %s, %s, %s, %s)",
                        (first_name, last_name, email, username, password))
            mysql.connection.commit()
            cur.close()
            flash('You are now registered and can log in', 'success')
            return redirect(url_for('login'))
    return render_template('signUp.html', form=form)


class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=100)])
    password = PasswordField('Password', [
        validators.DataRequired(),
    ])


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session and session['logged_in'] == True:
        flash('You are already logged in', 'info')
        return redirect(url_for('addBlogs'))
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password_input = form.password.data

        cur = mysql.connection.cursor()

        result = cur.execute(
            "SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            data = cur.fetchone()
            userID = data['id']
            password = data['password']
            role = data['role']

            if sha256_crypt.verify(password_input, password):
                session['logged_in'] = True
                session['username'] = username
                session['role'] = role
                session['userID'] = userID
                flash('You are now logged in', 'success')
                return redirect(url_for('index'))
            else:
                error = 'Invalid Password'
                return render_template('login.html', form=form, error=error)

            cur.close()

        else:
            error = 'Username not found'
            return render_template('login.html', form=form, error=error)

    return render_template('login.html', form=form)


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Please login', 'info')
            return redirect(url_for('login'))
    return wrap


@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Add Blogs
@app.route('/addBlogs', methods=['GET', 'POST'])
@is_logged_in
def addBlogs():
    if request.method == 'POST':
        title = request.form['title']
        blog = request.form['blog']
        category = request.form['category']

        print(blog)

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute(
            "INSERT INTO blogs(user_id, username, title, blog, category) VALUES(%s, %s, %s, %s, %s)", (session['userID'], session['username'], title, blog, category))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Blog Successfully Posted', 'success')

        return redirect(url_for('addBlogs'))

    else:
        cur = mysql.connection.cursor()

        result = cur.execute(
            "SELECT * FROM blogs WHERE user_id = %s ORDER BY date DESC", [
                session['userID']]
        )

        if result > 0:
            blogs = cur.fetchall()
            for blog in blogs:
                if datetime.datetime.now() - blog['date'] < datetime.timedelta(days=0.5):
                    blog['date'] = timeago.format(
                        blog['date'], datetime.datetime.now())
                else:
                    blog['date'] = blog['date'].strftime(
                        '%d %B, %Y')
            return render_template('addBlogs.html', blogs=blogs)
        else:
            return render_template('addBlogs.html', result=result)

        # close the connections
        cur.close()
    return render_template('addBlogs.html')


@app.route('/blogs', methods=['GET', 'POST'])
def blogs():

    if request.method == 'POST':
        category = request.form['category']
        # Create cursor
        cur = mysql.connection.cursor()

        if category == "All":
            result = cur.execute("SELECT * FROM blogs")
        else:
            result = cur.execute(
                f"SELECT * FROM blogs WHERE category = \"{category}\"")
        if result > 0:
            blogs = cur.fetchall()
            for blog in blogs:
                blog['date'] = blog['date'].strftime('%d %B, %Y')
            return render_template('blogs.html', blogs=blogs)
        else:
            msg = f"No Blogs Found For {category}"
            return render_template('blogs.html', result=result, msg=msg)
        # Close connection
        cur.close()
    else:
        # Create cursor
        cur = mysql.connection.cursor()

        # Get latest blogs
        result = cur.execute("SELECT * FROM blogs ORDER BY date DESC")

        if result > 0:
            blogs = cur.fetchall()
            for blog in blogs:
                blog['date'] = blog['date'].strftime('%d %B, %Y')
            return render_template('blogs.html', blogs=blogs)
        else:
            flash('No Blogs Found', 'success')
            return redirect(url_for('addBlogs'))
        # Close connection
        cur.close()


class BlogForm(Form):
    title = StringField('Title', [validators.Length(min=1)])
    category = StringField('Category', [validators.Length(min=1)])
    blog = TextAreaField('Blog')


@app.route('/editBlog/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def editBlog(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get blog by id
    cur.execute("SELECT * FROM blogs WHERE id = %s", [id])

    blog = cur.fetchone()
    cur.close()
    # Get form
    form = BlogForm(request.form)

    # Populate blog form fields
    form.title.data = blog['title']
    form.category.data = blog['category']
    form.blog.data = blog['blog']

    if request.method == 'POST' and form.validate():
        title = request.form['title']
        category = request.form['category']
        blog = request.form['blog']

        # Create Cursor
        cur = mysql.connection.cursor()
        # Execute
        cur.execute("UPDATE blogs SET title=%s, blog=%s WHERE id = %s",
                    (title, blog, id))
        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Blog Updated', 'success')

        return redirect(url_for('addBlogs'))

    return render_template('editBlog.html', form=form)


@app.route('/deleteBlog/<string:id>', methods=['POST'])
@is_logged_in
def deleteBlog(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM blogs WHERE id = %s", [id])

    # Commit to DB
    mysql.connection.commit()

    # Close connection
    cur.close()

    flash('Blog Deleted', 'success')

    return redirect(url_for('addBlogs'))


@app.route('/blog/<string:id>')
@is_logged_in
def blog(id):
    cur = mysql.connection.cursor()

    # Get blog by id
    cur.execute("SELECT * FROM blogs WHERE id = %s", [id])

    blog = cur.fetchone()
    cur.close()
    return render_template('blog.html', blog=blog)


class RequestResetForm(Form):
    email = EmailField('Email address', [
                       validators.DataRequired(), validators.Email()])


@app.route("/reset_request", methods=['GET', 'POST'])
def reset_request():
    if 'logged_in' in session and session['logged_in'] == True:
        flash('You are already logged in', 'info')
        return redirect(url_for('index'))
    form = RequestResetForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data
        cur = mysql.connection.cursor()
        result = cur.execute(
            "SELECT id,username,email FROM users WHERE email = %s", [email])
        if result == 0:
            flash(
                'There is no account with that email. You must register first.', 'warning')
            return redirect(url_for('signup'))
        else:
            data = cur.fetchone()
            user_id = data['id']
            user_email = data['email']
            cur.close()
            s = Serializer(app.config['SECRET_KEY'], 1800)
            token = s.dumps({'user_id': user_id}).decode('utf-8')
            msg = Message('Password Reset Request',
                          sender='noreply@demo.com', recipients=[user_email])
            msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make password reset request then simply ignore this email and no changes will be made.
Note:This link is valid only for 30 mins from the time you requested a password change request.
'''
            mail.send(msg)
            flash(
                'An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)


class ResetPasswordForm(Form):
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if 'logged_in' in session and session['logged_in'] == True:
        flash('You are already logged in', 'info')
        return redirect(url_for('index'))
    s = Serializer(app.config['SECRET_KEY'])
    try:
        user_id = s.loads(token)['user_id']
    except:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM users WHERE id = %s", [user_id])
    data = cur.fetchone()
    cur.close()
    user_id = data['id']
    form = ResetPasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        password = sha256_crypt.encrypt(str(form.password.data))
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE users SET password = %s WHERE id = %s", (password, user_id))
        mysql.connection.commit()
        cur.close()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)


if __name__ == '__main__':
    app.run(debug=True)
