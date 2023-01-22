import flask
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from urllib.parse import urlparse, urljoin
from functools import wraps

Base = declarative_base()

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# setup login_manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth.login"
# function to make sure the url redirect is to the host and not malicious etc. used below with /login
# from https://web.archive.org/web/20120517003641/http://flask.pocoo.org/snippets/62/
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


# setup Gravatar for icons in comments
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CONFIGURE TABLES
class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    parent = relationship("User", back_populates="children")
    comments = relationship("Comment")


class User(UserMixin, db.Model, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    children = relationship("BlogPost", back_populates="parent")
    comments = relationship("Comment")


class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    blog_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    name = db.Column(db.String(1000))


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).filter_by(id=user_id).first()


@app.route('/')
def get_all_posts():
    logged_in = False
    is_admin = False
    if current_user.is_authenticated:  # if user is not AnonymousUserMixin (which has no id)
        logged_in = True
        print(current_user.id)
        if current_user.id == 1:
            is_admin = True
            print("is admin = true")
        else:
            is_admin = False
            print("is admin = false")
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=logged_in, is_admin=is_admin)


@app.route('/register', methods=["GET", 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # if user already exists, go to the login page
        if db.session.query(User).filter_by(email=form.email.data).first():
            print("user already in db")
            flash("User already exists, please login instead")
            return redirect(url_for("login"))
        with app.app_context():
            new_user = User(
                email=form.email.data,
                name=form.name.data,
                password=generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=10),
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            session['username'] = new_user.id
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    logged_in = current_user.is_authenticated
    form = LoginForm()
    if form.validate_on_submit():
        # check if user in db
        user = db.session.query(User).filter_by(email=form.email.data).first()
        if not user:
            print("user not in db")
            flash("Email incorrect")
            return redirect(url_for("login", form=form))

        # compare passwords
        if check_password_hash(user.password, form.password.data):
            login_user(user)
            session['username'] = user.id
            print("Logged in")
            # is_safe_url should check if the url is safe for redirects.
            # See http://flask.pocoo.org/snippets/62/ for an example.
            next = request.args.get('next')
            if not is_safe_url(next):
                return abort(400)
            return redirect(url_for("get_all_posts"))
        else:
            print("password incorrect")
            flash("Password incorrect")
            return redirect(url_for("login", form=form))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def show_post(post_id):
    form = CommentForm()
    logged_in = current_user.is_authenticated
    requested_post = BlogPost.query.get(post_id)
    comments = db.session.query(Comment).filter_by(blog_id=post_id).all()
    print(comments)
    gravatar_url_base = "https://www.gravatar.com/avatar/"

    # create comment in DB
    if form.validate_on_submit():
        with app.app_context():
            comment = Comment(
                text=form.comment.data,
                parent_id=current_user.id,
                blog_id=post_id,
                name=db.session.query(User).filter_by(id=current_user.id).first().name
            )
            db.session.add(comment)
            db.session.commit()
            print("posted comment")
            return render_template("post.html", post=requested_post, logged_in=logged_in, form=form, comments=comments)
    return render_template("post.html", post=requested_post, logged_in=logged_in, form=form, comments=comments)


@app.route("/about")
def about():
    logged_in = current_user.is_authenticated
    return render_template("about.html", logged_in=logged_in)


@app.route("/contact")
def contact():
    logged_in = current_user.is_authenticated
    return render_template("contact.html", logged_in=logged_in)


def admin_only(function):
    @wraps(function)
    def decorated_function():
        if not current_user.id == 1:
            print("not admin")
            return abort(400)
        return function()
    return decorated_function


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    logged_in = current_user.is_authenticated
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=logged_in)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    logged_in = current_user.is_authenticated
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, logged_in=logged_in))

    return render_template("make-post.html", form=edit_form, logged_in=logged_in)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    logged_in = current_user.is_authenticated
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', logged_in=logged_in))


if __name__ == "__main__":
    app.run(debug=True)
