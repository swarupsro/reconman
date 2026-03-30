from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.extensions import limiter
from app.forms import LoginForm
from app.models import User
from app.utils.audit import audit


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10/hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and user.is_active and user.check_password(form.password.data):
            login_user(user)
            audit("login_success", object_type="user", object_id=str(user.id), commit=True)
            next_url = request.args.get("next")
            return redirect(next_url or url_for("dashboard.index"))

        audit("login_failed", object_type="auth", object_id=form.username.data.strip(), commit=True)
        flash("Invalid username or password.", "danger")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout", object_type="user", object_id=str(current_user.id), commit=True)
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
