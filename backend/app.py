from flask import Flask, jsonify, request, abort, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash

from cors import fix_cors

db = SQLAlchemy()

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'asdasdasd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db.init_app(app)


@app.before_first_request
def create_tables():
    db.create_all()


# TABLES
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    initials = db.Column(db.String(5))
    price = db.Column(db.DECIMAL(10, 2))
    img = db.Column(db.String(1000))
    team = db.Column(db.Integer())

    def to_json(self):
        return {
            "name": self.name,
            "initials": self.initials,
            "price": self.price,
            "img": self.img,
            "team": self.team
        }


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    email = db.Column(db.String(50))
    team = db.Column(db.Integer())
    discordId = db.Column(db.String(50))

    def to_json(self):
        return {
            "name": self.name,
            "password": self.password,
            "email": self.email,
            "team": self.team,
            "discordId": self.discordId
        }


@app.route('/api/user', methods=["POST"])
def create_user():
    if not request.json:
        abort(400)
    new_user = User(
        name=request.json.get("name"),
        password=request.json.get("password"),
        email=request.json.get("email"),
        team=request.json.get("team"),
        discordId=request.json.get("discord")
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify(new_user.to_json()), 201

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))

    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))



@app.route('/api/product', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([product.to_json() for product in products])


@app.route("/api/product", methods=["POST"])
def create_ticket():
    if not request.json:
        abort(400)
    new_product = Product(
        name=request.json.get("name"),
        initials=request.json.get("initials"),
        price=request.json.get("price"),
        img=request.json.get("img"),
        team=request.json.get("team")
    )
    db.session.add(new_product)
    db.session.commit()

    return jsonify(new_product.to_json()), 201


@app.route("/", methods=["GET"])
def return_home():
    return "Hello World"


app.run()

# @app.route("/ticket/<int:id>", methods=["PUT"])
# def update_ticket(idd):
#     if not request.json:
#         abort(400)
#
#     ticket = Ticket.query.get(idd)
#     if ticket is None:
#         abort(404)
#
#     ticket.name = request.json.get("name", ticket.name)
#     ticket.phone = request.json.get("phone", ticket.phone)
#     ticket.material = request.json.get("material", ticket.material)
#     ticket.email = request.json.get("email", ticket.email)
#     ticket.location = request.json.get("location", ticket.location)
#     ticket.model = request.json.get("model", ticket.model)
#     ticket.img = request.json.get("img", ticket.img)
#
#     db.session.commit()
#
#     return jsonify(ticket.to_json())
