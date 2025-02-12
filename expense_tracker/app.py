import datetime

from flask import Flask, jsonify, request
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expenses.db'
app.config['JWT_SECRET_KEY'] = 'supersecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    date = db.Column(db.Date, nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        access_token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(days=1))
        return jsonify({'access_token': access_token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/expenses', methods=['POST'])
@jwt_required()
def add_expense():
    data = request.get_json()
    user_id = get_jwt_identity()
    new_expense = Expense(user_id=user_id, amount=data['amount'], category=data['category'], 
                          description=data.get('description', ''), date=datetime.datetime.strptime(data['date'], '%Y-%m-%d').date(),
                          payment_method=data['payment_method'])
    db.session.add(new_expense)
    db.session.commit()
    return jsonify({'message': 'Expense added successfully'}), 201

@app.route('/expenses', methods=['GET'])
@jwt_required()
def get_expenses():
    user_id = get_jwt_identity()
    expenses = Expense.query.filter_by(user_id=user_id).all()
    expenses_list = [{'id': exp.id, 'amount': exp.amount, 'category': exp.category, 'description': exp.description, 
                      'date': exp.date.strftime('%Y-%m-%d'), 'payment_method': exp.payment_method} for exp in expenses]
    return jsonify(expenses_list)

# Flask-Admin setup
admin = Admin(app, name='Expense Tracker Admin', template_mode='bootstrap3')
admin.add_view(ModelView(User, db.session, endpoint='user_admin'))
admin.add_view(ModelView(Expense, db.session, endpoint='expense_admin'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
