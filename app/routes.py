# app/routes.py

from flask import Blueprint, render_template, url_for, flash, redirect, request
from app import db, bcrypt
from app.forms import RegistrationForm, LoginForm, SearchForm
from app.models import User, Friendship
from flask_login import login_user, current_user, logout_user, login_required

bp = Blueprint('main', __name__)

@bp.route("/")
@bp.route("/home")
def home():
    return render_template('home.html')

@bp.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', title='Register', form=form)

@bp.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('main.home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@bp.route("/search", methods=['GET', 'POST'])
@login_required
def search():
    form = SearchForm()
    users = []
    if form.validate_on_submit():
        users = User.query.filter(User.username.like(f"%{form.username.data}%")).all()
    return render_template('search.html', title='Search', form=form, users=users)

@bp.route("/add_friend/<int:user_id>")
@login_required
def add_friend(user_id):
    user = User.query.get(user_id)
    if user:
        friendship = Friendship(user_id=current_user.id, friend_id=user_id)
        db.session.add(friendship)
        db.session.commit()
        flash(f'You have added {user.username} as a friend!', 'success')
    else:
        flash('User not found', 'danger')
    return redirect(url_for('main.search'))
