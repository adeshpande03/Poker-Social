# app/routes.py

from flask import Blueprint, render_template, url_for, flash, redirect, request
from app import db, bcrypt
from app.forms import RegistrationForm, LoginForm, SearchForm
from app.models import User, Friendship, FriendRequest, BlockedUser
from flask_login import login_user, current_user, logout_user, login_required

bp = Blueprint("main", __name__)


@bp.route("/")
@bp.route("/home")
def home():
    return render_template("home.html")


@bp.route("/info")
def info():
    return render_template("info.html", title="Info")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return {"status": "success", "redirect_url": url_for("main.home")}
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        user = User(
            username=form.username.data, email=form.email.data, password=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        return {"status": "success", "redirect_url": url_for("main.login")}
    elif request.method == "POST":
        # Collect form errors
        errors = form.errors
        return {
            "status": "error",
            "message": "Registration failed",
            "errors": errors,
        }, 400
    return render_template("register.html", title="Register", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(
            (User.email == form.login.data) | (User.username == form.login.data)
        ).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for("main.home"))
        else:
            flash(
                "Login Unsuccessful. Please check email/username and password", "danger"
            )
    return render_template("login.html", title="Login", form=form)


@bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("main.home"))


@bp.route("/search", methods=["GET", "POST"])
@login_required
def search():
    form = SearchForm()
    users = []
    if form.validate_on_submit():
        users = (
            User.query.filter(User.username.like(f"%{form.username.data}%"))
            .filter(User.id != current_user.id)
            .all()
        )
    return render_template("search.html", title="Search", form=form, users=users)


@bp.route("/send_request/<int:user_id>")
@login_required
def send_request(user_id):
    user = User.query.get(user_id)
    if user:
        # Check if the user is already a friend
        friendship = Friendship.query.filter(
            (
                (Friendship.user_id == current_user.id)
                & (Friendship.friend_id == user_id)
            )
            | (
                (Friendship.user_id == user_id)
                & (Friendship.friend_id == current_user.id)
            )
        ).first()
        if friendship:
            flash(f"{user.username} is already your friend", "info")
            return redirect(url_for("main.search"))

        # Check if there is already a pending friend request
        existing_request = FriendRequest.query.filter_by(
            sender_id=current_user.id, receiver_id=user_id
        ).first()
        if existing_request:
            flash(f"You have already sent a friend request to {user.username}", "info")
        else:
            friend_request = FriendRequest(
                sender_id=current_user.id, receiver_id=user_id
            )
            db.session.add(friend_request)
            db.session.commit()
            flash(f"Friend request sent to {user.username}!", "success")
    else:
        flash("User not found", "danger")
    return redirect(url_for("main.search"))


@bp.route("/friend_requests")
@login_required
def friend_requests():
    requests = FriendRequest.query.filter_by(receiver_id=current_user.id).all()
    return render_template(
        "friend_requests.html", title="Friend Requests", requests=requests
    )


@bp.route("/accept_request/<int:request_id>")
@login_required
def accept_request(request_id):
    friend_request = FriendRequest.query.get(request_id)
    if friend_request and friend_request.receiver_id == current_user.id:
        friendship = Friendship(
            user_id=friend_request.sender_id, friend_id=friend_request.receiver_id
        )
        db.session.add(friendship)
        db.session.delete(friend_request)
        db.session.commit()
        flash("Friend request accepted!", "success")
    else:
        flash(
            "Friend request not found or you do not have permission to accept it",
            "danger",
        )
    return redirect(url_for("main.friend_requests"))


@bp.route("/reject_request/<int:request_id>")
@login_required
def reject_request(request_id):
    friend_request = FriendRequest.query.get(request_id)
    if friend_request and friend_request.receiver_id == current_user.id:
        db.session.delete(friend_request)
        db.session.commit()
        flash("Friend request rejected", "info")
    else:
        flash(
            "Friend request not found or you do not have permission to reject it",
            "danger",
        )
    return redirect(url_for("main.friend_requests"))


@bp.route("/friends")
@login_required
def friends():
    # Retrieve friends where the current user is the user or the friend
    friends = Friendship.query.filter(
        (Friendship.user_id == current_user.id)
        | (Friendship.friend_id == current_user.id)
    ).all()
    # Extract the actual user objects from the Friendship objects
    friend_users = []
    for friendship in friends:
        if friendship.user_id == current_user.id:
            friend_users.append(User.query.get(friendship.friend_id))
        else:
            friend_users.append(User.query.get(friendship.user_id))

    # Retrieve blocked users
    blocked_users = BlockedUser.query.filter_by(user_id=current_user.id).all()

    return render_template(
        "friends.html",
        title="Friends",
        friends=friend_users,
        blocked_users=blocked_users,
    )


@bp.route("/remove_friend/<int:user_id>")
@login_required
def remove_friend(user_id):
    friendship = Friendship.query.filter(
        (Friendship.user_id == current_user.id) & (Friendship.friend_id == user_id)
        | (Friendship.user_id == user_id) & (Friendship.friend_id == current_user.id)
    ).first()
    if friendship:
        db.session.delete(friendship)
        db.session.commit()
        flash("Friend removed", "info")
    else:
        flash("Friendship not found", "danger")
    return redirect(url_for("main.friends"))


@bp.route("/block_user/<int:user_id>")
@login_required
def block_user(user_id):
    user = User.query.get(user_id)
    if user:
        blocked_user = BlockedUser(user_id=current_user.id, blocked_user_id=user_id)
        db.session.add(blocked_user)
        db.session.commit()
        # Also remove any existing friendship
        friendship = Friendship.query.filter(
            (Friendship.user_id == current_user.id) & (Friendship.friend_id == user_id)
            | (Friendship.user_id == user_id)
            & (Friendship.friend_id == current_user.id)
        ).first()
        if friendship:
            db.session.delete(friendship)
            db.session.commit()
        flash(f"User {user.username} has been blocked", "info")
    else:
        flash("User not found", "danger")
    return redirect(url_for("main.friends"))


@bp.route("/unblock_user/<int:user_id>")
@login_required
def unblock_user(user_id):
    blocked_user = BlockedUser.query.filter_by(
        user_id=current_user.id, blocked_user_id=user_id
    ).first()
    if blocked_user:
        db.session.delete(blocked_user)
        db.session.commit()
        flash(f"User {blocked_user.blocked_user_id} has been unblocked", "success")
    else:
        flash("User not found or not blocked", "danger")
    return redirect(url_for("main.friends"))
