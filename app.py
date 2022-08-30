import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    shares = db.execute(
        "SELECT symbol, stock_name, transaction_type, SUM(shares_count) AS count, date FROM transactions WHERE user_id = ? GROUP BY symbol HAVING (SUM(shares_count)) > 0;",
        user_id
    )

    total_cash_stocks = 0
    for share in shares:
        quote = lookup(share["symbol"])
        share["price"] = quote["price"]
        share["total"] = share["price"] * share["count"]
        total_cash_stocks = total_cash_stocks + share["total"]

    cash_balance = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash_balance = cash_balance[0]["cash"]

    grand_total = cash_balance + total_cash_stocks

    return render_template("index.html", shares=shares, cash=cash_balance, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure stock symbol was submitted and it is valid
        stock = lookup(request.form.get("symbol"))
        shares = request.form.get("shares")
        if not request.form.get("symbol") or not stock:
            return apology("must provide stock symbol", 400)
        # Ensure quantity of shares is not a negative or fractional number
        if not shares.isnumeric() or not float(shares).is_integer():
            return apology("shares number is invalid", 400)
        elif int(request.form.get("shares")) < 1:
            return apology("shares number cannot be less than 1", 400)

        # Calculate the total sum of purchase
        price = stock["price"]
        total_sum = float(price * int(request.form.get("shares")))

        # Ensure user has enough money
        user_id = session["user_id"]

        row = db.execute(
            "SELECT * FROM users WHERE id = ?",
            user_id
        )
        cash = row[0]["cash"]

        if (cash - total_sum) < 0:
            return apology("you cannot afford this purchase", 400)

        # Update the db to save transactions history
        db.execute(
            "INSERT INTO transactions (user_id, stock_name, symbol, shares_count, price, transaction_type) VALUES (?, ?, ?, ?, ?, ?)",
            user_id, stock["name"], stock["symbol"], request.form.get("shares"), price, "BOUGHT"
        )

        updated_cash = cash - total_sum
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?", updated_cash, user_id
        )

        flash("Bought!")
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]

    shares = db.execute(
        "SELECT * FROM transactions WHERE user_id = ?",
        user_id
    )

    return render_template("history.html", shares=shares)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?",
            request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        stock = lookup(request.form.get("symbol"))
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 400)
        elif stock is None:
            return apology("must provide a valid symbol", 400)
        else:
            return render_template("quoted.html", name=stock["name"], price=stock["price"], symbole=stock["symbol"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)
        # Ensure username is unique
        existing_users = db.execute(
            "SELECT * FROM users WHERE username = ?",
            request.form.get("username")
        )
        if len(existing_users) == 1:
            return apology("This username already exists", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Ensure password matches
        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("password does not match", 400)

        password = generate_password_hash(request.form.get("password"), "sha256")

        # Add a new user to db
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), password)

        # Redirect user to home page
        flash("Registration successful")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    symbols = db.execute(
        "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol",
        user_id
    )
    SYMBOLS = []
    for k in symbols:
        SYMBOLS.append(k['symbol'])
    print(SYMBOLS)

    shares_owned = db.execute(
        "SELECT symbol, SUM(shares_count) AS count FROM transactions WHERE user_id = ? and transaction_type = ? GROUP BY symbol",
        user_id, "BOUGHT"
    )

    if request.method == "POST":
        stock_to_sell = request.form.get("symbol")
        amount_to_sell = int(request.form.get("shares"))

        # Ensure stock is selected correctly
        if not stock_to_sell:
            return apology("must provide stock symbol", 400)
        elif stock_to_sell not in SYMBOLS:
            return apology("you do not own this stock", 400)
        # Ensure number of shares is selected correctly
        elif amount_to_sell < 1:
            return apology("shares number cannot be less than 1", 400)

        selected_stock = [x for x in shares_owned if x["symbol"] == stock_to_sell][0]
        print("Selected stock {}".format(selected_stock))
        owned_shares = selected_stock["count"]
        if owned_shares < amount_to_sell:
            return apology("you do not have enough shares", 400)

        # Calculate the total sum of transaction
        stock = lookup(request.form.get("symbol"))
        price = stock["price"]
        sold_total_price = float(price * amount_to_sell)

        # Update the cash balance
        row = db.execute(
            "SELECT * FROM users WHERE id = ?",
            user_id
        )
        cash = row[0]["cash"]
        updated_cash = cash + sold_total_price
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            updated_cash, user_id
        )

        # Update the transactions history
        db.execute(
            "INSERT INTO transactions (user_id, stock_name, symbol, shares_count, price, transaction_type) VALUES (?, ?, ?, ?, ?, ?)",
            user_id, stock["name"], stock_to_sell, -amount_to_sell, price, "SOLD"
        )

        flash("Sold!")
        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("sell.html", symbols=SYMBOLS)

@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Add cash to user's balance"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        user_id = session["user_id"]
        add = request.form.get("add")
        # Ensure sum is not a negative or fractional number
        if not add.isnumeric() or not float(add).is_integer():
            return apology("Sum is invalid", 400)
        elif int(request.form.get("add")) < 1:
            return apology("Top up sum cannot be less than 1 USD", 400)

        db.execute(
            "UPDATE users SET cash = cash + ? WHERE id = ?",
            add, user_id
        )

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("add.html")