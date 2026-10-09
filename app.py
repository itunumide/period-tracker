import os
from functools import wraps

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "dev-secret-change-me"
)
app.config["DATABASE"] = os.environ.get(
    "DATABASE", "periods.db"
)

# =========================================================
# AUTHENTICATION
# =========================================================

def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "error")
            return redirect(url_for("signin"))
        return view(**kwargs)

    return wrapped_view


def get_current_user():
    user_id = session.get("user_id")

    if user_id is None:
        return None

    return get_db().execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

@app.route("/")
def home():
    return render_template("index.html")

# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name:
            flash("Please enter your name.", "error")
            return render_template("register.html")

        if not email:
            flash("Please enter your email address.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        db = get_db()

        existing_user = db.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if existing_user:
            flash(
                "An account with this email already exists.",
                "error",
            )
            return render_template("register.html")

        cursor = db.execute(
            """
            INSERT INTO users (name, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (name, email, generate_password_hash(password)),
        )

        user_id = cursor.lastrowid

        db.execute(
            """
            INSERT INTO user_settings (
                user_id,
                average_cycle_length,
                average_period_length
            )
            VALUES (?, ?, ?)
            """,
            (user_id, DEFAULT_CYCLE_LENGTH, DEFAULT_PERIOD_LENGTH),
        )

        db.commit()

        session.clear()
        session["user_id"] = user_id

        flash("Your account has been created successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html")


# =========================================================
# SIGN IN
# =========================================================

@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter your email and password.", "error")
            return render_template("signin.html")

        user = get_db().execute(
            "SELECT * FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if user is None or not check_password_hash(
            user["password_hash"], password
        ):
            flash("Incorrect email or password.", "error")
            return render_template("signin.html")

        session.clear()
        session["user_id"] = user["id"]

        flash(f"Welcome back, {user['name']}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("signin.html")


# =========================================================
# SIGN OUT
# =========================================================

@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("landing"))

app.run(debug=True)

