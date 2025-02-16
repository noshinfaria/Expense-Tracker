from flask import Flask
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

from . import create_app  # Use relative imports
from .models import Budget, Category, Expense, User, db  # Use relative imports

# Create your Flask app using the create_app function
app = create_app()

# Create an admin interface
admin = Admin(app, name='Expense Tracker Admin', template_mode='bootstrap3')

# Customizing the ModelView for User
class UserModelView(ModelView):
    column_list = ('id', 'username', 'email', 'created_at')
    form_columns = ('username', 'email', 'password_hash')

# Customizing the ModelView for Category
class CategoryModelView(ModelView):
    column_list = ('id', 'name', 'user_id')
    form_columns = ('name', 'user_id')

# Customizing the ModelView for Expense
class ExpenseModelView(ModelView):
    column_list = ('id', 'user_id', 'amount', 'category_id', 'description', 'date', 'payment_method')
    form_columns = ('user_id', 'amount', 'category_id', 'description', 'date', 'payment_method', 'recurrence_type', 'recurrence_interval', 'next_occurrence_date')

# Customizing the ModelView for Budget
class BudgetModelView(ModelView):
    column_list = ('id', 'user_id', 'amount', 'month')
    form_columns = ('user_id', 'amount', 'month')

# Add views for your models
admin.add_view(UserModelView(User, db.session))
admin.add_view(CategoryModelView(Category, db.session))
admin.add_view(ExpenseModelView(Expense, db.session))
admin.add_view(BudgetModelView(Budget, db.session))

# Run the application
if __name__ == '__main__':
    app.run(debug=True)
