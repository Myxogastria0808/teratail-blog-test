from flask import Flask, render_template, redirect, session, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, SubmitField, TextAreaField
from datetime import timedelta
from flask_talisman import Talisman, ALLOW_FROM
#秘密鍵の生成
import os


app = Flask(__name__)

#CSP start
csp = {
    'default-src': [
        '\'self\'',
        '*.google.com',
        '*.google-analytics.com',
        '*.gstatic.com',
    ]
}
talisman = Talisman(app, content_security_policy=csp)
#CSP end

#session start
app.permanent_session_lifetime = timedelta(days=1)
#session end

#flask-login start
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24)
app.config['WTF_CSRF_ENABLED'] = True
#ハッシュ化関数
bcrypt = Bcrypt(app)

class PasswordForm(FlaskForm):
    password = PasswordField('パスワード')
    submit = SubmitField('ログイン')

class LoginForm(FlaskForm):
    email = EmailField('メールアドレス')
    password = PasswordField('パスワード')
    submit = SubmitField('ログイン')

class RegisterForm(FlaskForm):
    username = StringField('ユーザー名')
    email = EmailField('メールアドレス')
    password = PasswordField('パスワード')
    submit = SubmitField('登録')

class UpdateForm(FlaskForm):
    username = StringField('ユーザー名')
    email = EmailField('メールアドレス')
    submit = SubmitField('更新')

class BlogCreateForm(FlaskForm):
    title = StringField('タイトル')
    context = TextAreaField('内容')
    submit = SubmitField('作成')

class BlogUpdateForm(FlaskForm):
    title = StringField('タイトル')
    context = TextAreaField('内容')
    submit = SubmitField('更新')
#flask-wtf end
#ユーザー情報の読み込み
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
#flask-login end

#DB setting start
SQLALCHEMY_DATABASE_URI = "mysql+pymysql://{username}:{password}@{hostname}/{databasename}".format(
    username="root",
    password="123abc",
    hostname="localhost",
    databasename="graduate2",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

class Blog(db.Model):
    __tablename__ = 'blog'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text(), nullable=False)
    context = db.Column(db.Text(), nullable=False)
    img = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    def __init__(self, title, context, img, user_id):
        self.title = title
        self.context = context
        self.img = img
        self.user_id = user_id

with app.app_context():
    db.create_all()
#DB setting end


@app.route('/')
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def jump():
    return redirect('/password')

@app.route('/password', methods=['GET', 'POST'])
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def password():
    form = PasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        if password=='em0AWF0egXGEB4rNl39v':
            session.permanent = True
            session['login'] = True
            return redirect('/top')
        else:
            render_template('password-failed.html')
    else:
        return render_template('password.html', form=form)

@app.route('/top', methods=['GET', 'POST'])
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def top():
    if 'login' in session and session['login'] and request.method == 'GET':
        # blog = Blog.query.all()
        blog = Blog.query.join(User, User.id == Blog.user_id).add_columns(Blog.id, Blog.title, Blog.context, Blog.img, User.username).all()
        return render_template('index.html', blog=blog)
    else:
        return redirect('/password')
    
@app.route('/logout', methods=['GET'])
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def logout():
    if 'login' in session and session['login']:
        if request.method == 'GET':
            session.pop('login', None)
            return redirect('/password')

@app.route('/<int:id>/blog', methods=['GET'])
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def blog(id):
    if 'login' in session and session['login']:
        blog = Blog.query.get(id)
        if request.method == 'GET':
            return render_template('blog.html', blog=blog)
    else:
        return redirect('/password')


@app.route('/login', methods=['GET', 'POST'])
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def login():
    if 'login' in session and session['login']:
        form = LoginForm()
        if form.validate_on_submit():
            email = form.email.data
            password= form.password.data
            user = User.query.filter_by(email=email).one_or_none()
            if user is None or not bcrypt.check_password_hash(user.password, password) == True:
                return render_template('login-failed.html')
            login_user(user)
            return redirect(app.url_for('mypage', id=user.id))
        else:
            return render_template('login.html', form=form)
    else:
        return redirect('/password')

@app.route('/signup', methods=['GET', 'POST'])
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def signup():
    if 'login' in session and session['login']:
        form = RegisterForm()
        if form.validate_on_submit():
            username = form.username.data
            email = form.email.data
            password = form.password.data
            user = User(username=username, email=email,  password=bcrypt.generate_password_hash(password).decode('utf-8'))
            db.session.add(user)
            db.session.commit()
            return redirect('/login')
        else:
            return render_template('signup.html', form=form)
    else:
        return redirect('/password')

@app.route('/bloglogout', methods=['GET'])
@login_required
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def bloglogout():
    if 'login' in session and session['login']:
        if request.method == 'GET':
            logout_user()
            return redirect('/top')

@app.route('/<int:id>/blogcreate', methods=['GET', 'POST'])
@login_required
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def blogcreate(id):
    if 'login' in session and session['login']:
        form = BlogCreateForm()
        if form.validate_on_submit():
            title = form.title.data
            context = form.context.data
            img = id%4
            blog = Blog(title=title, context=context, user_id=id, img=img)
            db.session.add(blog)
            db.session.commit()
            user = User.query.get(id)
            return redirect(app.url_for('mypage', id=user.id))
        else:
            user = User.query.get(id)
            return render_template('blogcreate.html', form=form, user=user)
    else:
        logout_user()
        return redirect('/password')

@app.route('/<int:user_id>/<int:blog_id>/blogupdate', methods=['GET', 'POST'])
@login_required
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def blogupdate(blog_id, user_id):
    if 'login' in session and session['login']:
        form = BlogUpdateForm()
        blog = Blog.query.get(blog_id)
        if form.validate_on_submit():
            blog.title = form.title.data
            blog.context = form.context.data
            blog.img = blog_id%4
            db.session.commit()
            user = User.query.get(user_id)
            return redirect(app.url_for('mypage', id=user.id))
        else:
            form.title.data = blog.title
            form.context.data = blog.context
            user = User.query.get(user_id)
            return render_template('blogupdate.html', form=form, user=user)
    else:
        logout_user()
        return redirect('/password')

@app.route('/<int:user_id>/<int:blog_id>/blogdelete', methods=['GET'])
@login_required
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def blogdelete(blog_id, user_id):
    if 'login' in session and session['login']:
        blog = Blog.query.get(blog_id)
        if request.method == 'GET':
            db.session.delete(blog)
            db.session.commit()
            user = User.query.get(user_id)
            return redirect(app.url_for('mypage', id=user.id))
    else:
        logout_user()
        return redirect('/password')

@app.route('/<int:id>/mypage', methods=['GET'])
@login_required
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def mypage(id):
    if 'login' in session and session['login']:
        if request.method == 'GET':
            user = User.query.get(id)
            blog = Blog.query.filter_by(user_id=id).all()
            return render_template('mypage.html', user=user, blog=blog)
    else:
        logout_user()
        return redirect('/password')

@app.route('/<int:id>/update', methods=['GET', 'POST'])
@login_required
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def update(id):
    if 'login' in session and session['login']:
        form = UpdateForm()
        user = User.query.get(id)
        if form.validate_on_submit():
            user.username = form.username.data
            user.email = form.email.data
            db.session.commit()
            user = User.query.get(id)
            return redirect(app.url_for('mypage', id=user.id))
        else:
            form.username.data = user.username
            form.email.data = user.email
            return render_template('update.html', form=form, user=user)
    else:
        logout_user()
        return redirect('/password')


@app.errorhandler(404)
def error_404(error):
    return render_template('404.html')

@app.errorhandler(500)
def error_404(error):
    return render_template('500.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)