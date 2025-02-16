from datetime import datetime, timedelta
# 
import jwt
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Blueprint, Response, current_app, jsonify, request, url_for
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
)
from flask_mail import Message
from sqlalchemy import Enum, func, create_engine


from werkzeug.security import check_password_hash, generate_password_hash
from langchain.llms import LlamaCpp

from . import bcrypt, db, mail
from .models import Budget, Category, Expense, RecurrenceType, User
from .config import Config  

llm = LlamaCpp(model_path="./models/llama-2-7b.Q4_K_M.gguf", n_ctx=512, temperature=0.7)

main = Blueprint('main', __name__)

# Create the SQLAlchemy engine
engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)

# Authentication
@main.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@main.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token})
    return jsonify({'message': 'Invalid credentials'}), 401

@main.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    new_access_token = create_access_token(identity=identity)
    return jsonify({'access_token': new_access_token}), 200

@main.route('/reset_password_request', methods=['POST'])
def reset_password_request():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if user:
        token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + timedelta(hours=1)},
                           current_app.config['JWT_SECRET_KEY'], algorithm='HS256')
        
        reset_url = url_for('reset_password', token=token, _external=True)
        msg = Message('Password Reset Request', recipients=[data['email']])
        msg.body = f'Please click the following link to reset your password: {reset_url}'
        mail.send(msg)

        return jsonify({'message': 'Password reset email sent'}), 200
    return jsonify({'message': 'Email not found'}), 404


@main.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    try:
        data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        
        if user:
            new_password = request.get_json()['password']
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password_hash = hashed_password
            db.session.commit()
            return jsonify({'message': 'Password has been reset'}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid Authentication Token'}), 403

    return jsonify({'message': 'User not found'}), 404


# Expense Apis

@main.route('/expenses', methods=['POST'])
@jwt_required()
def add_expense():
    data = request.get_json()
    user_id = get_jwt_identity()

    # Validate the presence of required fields
    if not data or 'amount' not in data or 'category_id' not in data or 'date' not in data or 'payment_method' not in data:
        return jsonify({'message': 'Invalid input data, please provide amount, category_id, date, and payment_method'}), 400
    
    # Validate amount (must be a positive float)
    try:
        amount = float(data['amount'])
        if amount <= 0:
            return jsonify({'message': 'Amount must be a positive number'}), 400
    except ValueError:
        return jsonify({'message': 'Invalid amount format'}), 400

    # Validate category_id (must exist and belong to the user)
    category = Category.query.filter_by(id=data['category_id'], user_id=user_id).first()
    if not category:
        return jsonify({'message': 'Invalid category or category does not belong to the user'}), 400

    # Validate payment method
    allowed_payment_methods = {"cash", "credit card", "debit card", "paypal", "bank transfer"}
    payment_method = data['payment_method'].lower()
    if payment_method not in allowed_payment_methods:
        return jsonify({'message': 'Invalid payment method'}), 400

    # Validate date (must be in the correct format)
    try:
        expense_date = datetime.datetime.strptime(data['date'], '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'message': 'Invalid date format, expected YYYY-MM-DD'}), 400

    # Create new expense
    new_expense = Expense(
        user_id=user_id,
        amount=amount,
        category_id=category.id,
        description=data.get('description', ''),
        date=expense_date,
        payment_method=payment_method,

        # for recurring event
        recurrence_type=data.get('recurrence_type'),  # e.g., "monthly"
        recurrence_interval=data.get('recurrence_interval', 1),  # default to every 1
        next_occurrence_date=data['date']  # Set initial occurrence date
    )

    # Add the new expense to the database
    db.session.add(new_expense)
    db.session.commit()

    return jsonify({'message': 'Expense added successfully'}), 201




@main.route('/expenses', methods=['GET'])
@jwt_required()
def get_expenses():
    user_id = get_jwt_identity()
    expenses = Expense.query.filter_by(user_id=user_id).all()

    expenses_list = [
        {
            'id': exp.id,
            'amount': exp.amount,
            'category': exp.category.name,
            'description': exp.description,
            'date': exp.date.strftime('%Y-%m-%d'),
            'payment_method': exp.payment_method
        }
        for exp in expenses
    ]

    return jsonify(expenses_list)


@main.route('/expenses/filter', methods=['GET'])
@jwt_required()
def filter_expenses():
    user_id = get_jwt_identity()
    
    # Get optional query parameters
    category_name = request.args.get('category_name')
    start_date = request.args.get('start_date')  # Expected format: YYYY-MM-DD
    end_date = request.args.get('end_date')      # Expected format: YYYY-MM-DD
    
    # Start building the query
    query = Expense.query.filter_by(user_id=user_id)

    # Filter by category name if provided
    if category_name:
        query = query.join(Category).filter(Category.name.ilike(f'%{category_name}%'))

    # Filter by date range if provided
    if start_date and end_date:
        try:
            start_date_obj = datetime.datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.datetime.strptime(end_date, '%Y-%m-%d').date()
            query = query.filter(Expense.date.between(start_date_obj, end_date_obj))
        except ValueError:
            return jsonify({'message': 'Invalid date format, expected YYYY-MM-DD'}), 400

    # Fetch filtered expenses
    expenses = query.all()

    # Format the response
    expenses_list = [
        {
            'id': exp.id,
            'amount': exp.amount,
            'category': exp.category.name,
            'description': exp.description,
            'date': exp.date.strftime('%Y-%m-%d'),
            'payment_method': exp.payment_method
        }
        for exp in expenses
    ]

    return jsonify(expenses_list), 200


@main.route('/expenses/summary', methods=['GET'])
@jwt_required()
def get_expense_summary():
    user_id = get_jwt_identity()

    # Total expenses
    total_expenses = db.session.query(db.func.sum(Expense.amount)).filter_by(user_id=user_id).scalar() or 0

    # Monthly breakdown
    monthly_breakdown = (
        db.session.query(
            db.func.strftime('%Y-%m', Expense.date).label('month'),
            db.func.sum(Expense.amount).label('total_amount')
        )
        .filter_by(user_id=user_id)
        .group_by('month')
        .order_by('month')
        .all()
    )

    monthly_data = [
        {
            'month': row.month,
            'total_amount': row.total_amount
        }
        for row in monthly_breakdown
    ]

    # Top 3 categories by spending
    top_categories = (
        db.session.query(
            Category.name,
            db.func.sum(Expense.amount).label('total_amount')
        )
        .join(Expense)
        .filter(Expense.user_id == user_id)
        .group_by(Category.name)
        .order_by(db.func.sum(Expense.amount).desc())
        .limit(3)
        .all()
    )

    top_categories_data = [
        {
            'category': row.name,
            'total_amount': row.total_amount
        }
        for row in top_categories
    ]

    # Prepare the summary response
    summary_response = {
        'total_expenses': total_expenses,
        'monthly_breakdown': monthly_data,
        'top_categories': top_categories_data
    }

    return jsonify(summary_response), 200


@main.route('/expenses/<int:expense_id>', methods=['PUT'])
@jwt_required()
def update_expense(expense_id):
    user_id = get_jwt_identity()

    # Find the expense by ID
    expense = Expense.query.filter_by(id=expense_id, user_id=user_id).first()

    # Check if the expense exists
    if expense is None:
        return jsonify({'error': 'Expense not found or you do not have permission to update it.'}), 404

    data = request.get_json()

    # Update fields if provided
    if 'amount' in data:
        if isinstance(data['amount'], (int, float)) and data['amount'] > 0:
            expense.amount = data['amount']
        else:
            return jsonify({'error': 'Invalid amount. Must be a positive number.'}), 400

    if 'category_id' in data:
        category = Category.query.filter_by(id=data['category_id'], user_id=user_id).first()
        if category:
            expense.category_id = category.id
        else:
            return jsonify({'error': 'Invalid category.'}), 400

    if 'description' in data:
        expense.description = data['description']

    if 'payment_method' in data:
        allowed_payment_methods = {"cash", "credit card", "debit card", "paypal", "bank transfer"}
        if data['payment_method'].lower() in allowed_payment_methods:
            expense.payment_method = data['payment_method'].lower()
        else:
            return jsonify({'error': 'Invalid payment method.'}), 400

    # Commit changes to the database
    db.session.commit()

    return jsonify({'message': 'Expense updated successfully.'}), 200



@main.route('/expenses/<int:expense_id>', methods=['DELETE'])
@jwt_required()
def delete_expense(expense_id):
    user_id = get_jwt_identity()

    # Find the expense by ID
    expense = Expense.query.filter_by(id=expense_id, user_id=user_id).first()

    # Check if the expense exists
    if expense is None:
        return jsonify({'error': 'Expense not found or you do not have permission to delete it.'}), 404

    # Delete the expense
    db.session.delete(expense)
    db.session.commit()

    return jsonify({'message': 'Expense deleted successfully.'}), 200


def generate_recurring_expenses():
    today = datetime.today().date()
    expenses = Expense.query.filter(Expense.next_occurrence_date <= today).all()
    
    for expense in expenses:
        # Create a new expense
        new_expense = Expense(
            user_id=expense.user_id,
            amount=expense.amount,
            category_id=expense.category_id,
            description=expense.description,
            date=today,
            payment_method=expense.payment_method
        )
        
        # Update the next occurrence date
        if expense.recurrence_type == RecurrenceType.DAILY:
            expense.next_occurrence_date += timedelta(days=1)
        elif expense.recurrence_type == RecurrenceType.WEEKLY:
            expense.next_occurrence_date += timedelta(weeks=expense.recurrence_interval)
        elif expense.recurrence_type == RecurrenceType.MONTHLY:
            expense.next_occurrence_date = (expense.next_occurrence_date + 
                                             timedelta(days=30 * expense.recurrence_interval)).replace(day=1)
        elif expense.recurrence_type == RecurrenceType.YEARLY:
            expense.next_occurrence_date = (expense.next_occurrence_date + 
                                             timedelta(days=365 * expense.recurrence_interval)).replace(day=1, month=1)

        db.session.add(new_expense)
    
    db.session.commit()

# Scheduler to run the function daily
scheduler = BackgroundScheduler()
scheduler.add_job(generate_recurring_expenses, 'interval', days=1)
scheduler.start()


# Category Apis

@main.route('/categories', methods=['POST'])
@jwt_required()
def add_category():
    data = request.get_json()
    user_id = get_jwt_identity()

    if 'name' not in data or not data['name'].strip():
        return jsonify({'message': 'Category name is required'}), 400

    new_category = Category(name=data['name'].strip(), user_id=user_id)
    db.session.add(new_category)
    db.session.commit()

    return jsonify({'message': 'Category created successfully', 'category_id': new_category.id}), 201


@main.route('/categories', methods=['GET'])
@jwt_required()
def get_categories():
    user_id = get_jwt_identity()
    categories = Category.query.filter_by(user_id=user_id).all()

    return jsonify([{'id': cat.id, 'name': cat.name} for cat in categories])


@main.route('/categories/<int:category_id>', methods=['PUT'])
@jwt_required()
def update_category(category_id):
    data = request.get_json()
    user_id = get_jwt_identity()

    category = Category.query.filter_by(id=category_id, user_id=user_id).first()
    if not category:
        return jsonify({'message': 'Category not found'}), 404

    if 'name' in data and data['name'].strip():
        category.name = data['name'].strip()
        db.session.commit()
        return jsonify({'message': 'Category updated successfully'})
    
    return jsonify({'message': 'Invalid data'}), 400


@main.route('/categories/<int:category_id>', methods=['DELETE'])
@jwt_required()
def delete_category(category_id):
    user_id = get_jwt_identity()
    
    category = Category.query.filter_by(id=category_id, user_id=user_id).first()
    if not category:
        return jsonify({'message': 'Category not found'}), 404

    # Check if there are any expenses using this category
    if Expense.query.filter_by(category_id=category_id).first():
        return jsonify({'message': 'Cannot delete category with existing expenses'}), 400

    db.session.delete(category)
    db.session.commit()

    return jsonify({'message': 'Category deleted successfully'})

# Budget Apis

@main.route('/budgets', methods=['POST'])
@jwt_required()
def set_budget():
    user_id = get_jwt_identity()
    data = request.get_json()

    # Get the current month
    month = datetime.now().replace(day=1)

    # Check if a budget for this month already exists
    existing_budget = Budget.query.filter_by(user_id=user_id, month=month).first()
    
    if existing_budget:
        return jsonify({'error': 'Budget for this month already exists. Please update it instead.'}), 400

    budget = Budget(
        user_id=user_id,
        amount=data['amount'],
        month=month
    )

    db.session.add(budget)
    db.session.commit()

    return jsonify({'message': 'Budget set successfully.'}), 201


def notify_budget_exceeded(user_email):
    subject = "Budget Exceeded Notification"
    body = "Dear user,\n\nYou have exceeded your monthly budget. Please review your expenses.\n\nBest regards,\nYour Budget Tracker Team"

    msg = Message(subject, recipients=[user_email])
    msg.body = body

    try:
        with main.app_context():
            mail.send(msg)
        print(f"Notification email sent to {user_email}")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")




@main.route('/budgets/usage', methods=['GET'])
@jwt_required()
def track_budget_usage():
    user_id = get_jwt_identity()
    month = datetime.now().replace(day=1)

    # Get the user’s budget for the current month
    budget = Budget.query.filter_by(user_id=user_id, month=month).first()

    if not budget:
        return jsonify({'error': 'No budget found for this month.'}), 404

    # Calculate total expenses for the current month
    total_expenses = db.session.query(func.sum(Expense.amount)).filter(
        Expense.user_id == user_id,
        func.extract('year', Expense.date) == month.year,
        func.extract('month', Expense.date) == month.month
    ).scalar() or 0

    budget_usage = {
        'budget_amount': budget.amount,
        'total_expenses': total_expenses,
        'remaining_budget': budget.amount - total_expenses,
        'exceeded': total_expenses > budget.amount
    }

    # Notify user if they exceeded their budget
    if budget_usage['exceeded']:
        user = User.query.get(user_id)
        notify_budget_exceeded(user.email)

    return jsonify(budget_usage), 200




@main.route('/export', methods=['GET'])
@jwt_required()
def export_expenses():
    user_id = get_jwt_identity()
    expenses = Expense.query.filter_by(user_id=user_id).all()

    # Create a CSV response
    def generate():
        yield "id,amount,category,description,date,payment_method\n"  # CSV header
        for exp in expenses:
            yield f"{exp.id},{exp.amount},{exp.category.name},{exp.description},{exp.date.strftime('%Y-%m-%d')},{exp.payment_method}\n"

    return Response(generate(), mimetype='text/csv', headers={"Content-Disposition": "attachment;filename=expenses.csv"})


@main.route('/update_profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    
    # Update email if provided
    if 'email' in data:
        user.email = data['email']
    
    db.session.commit()
    
    return jsonify({'message': 'Profile updated successfully'}), 200



@main.route('/change_password', methods=['PUT'])
@jwt_required()
def change_password():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    
    if 'current_password' not in data or 'new_password' not in data:
        return jsonify({'error': 'Current password and new password are required'}), 400

    # Check the current password
    if not check_password_hash(user.password, data['current_password']):
        return jsonify({'error': 'Current password is incorrect'}), 400

    user.password = generate_password_hash(data['new_password'])
    db.session.commit()

    return jsonify({'message': 'Password changed successfully'}), 200


# Chatbot

# Function to process user queries
def process_query(user_message, user_id):
    # Generate SQL query using Llama
    response = llm(f"Convert this finance request into an SQL query: {user_message}")

    # Extract SQL query
    sql_match = re.search(r"SELECT .*?;|UPDATE .*?;|INSERT INTO .*?;", response, re.DOTALL)
    
    if sql_match:
        sql_query = sql_match.group(0)
        sql_query = sql_query.replace("user_id = ?", f"user_id = {user_id}")  # Ensure user-specific filtering
        return run_sql_query(sql_query)
    else:
        return "Sorry, I couldn't process that request."

# Function to execute SQL queries
def run_sql_query(query):
    try:
        with engine.connect() as connection:
            result = connection.execute(text(query))
            if query.strip().lower().startswith("select"):
                data = result.fetchall()
                return [dict(row) for row in data]  # Convert result to JSON format
            return "Action completed successfully."
    except Exception as e:
        return f"Error executing query: {str(e)}"

# API Route for Chatbot
@app.route('/chat', methods=['POST'])
@jwt_required()
def chat():
    data = request.json
    user_message = data.get("message")
    user_id = get_jwt_identity()

    if not user_message:
        return jsonify({"error": "Message is required"}), 400

    response = process_query(user_message, user_id)
    
    return jsonify({"response": response})