# Finance Tracker

A finance tracking application built with Flask, providing user authentication, expense management, budgeting features, and more. This application allows users to register, log in, and manage their expenses effectively.

## Table of Contents

- [Features](#features)
- [Technologies](#technologies)
- [API Endpoints](#api-endpoints)

## Features

- **User Authentication**
  - Registration and login using JWT-based authentication.
  - Password reset feature via email (bonus).
  - Token expiration and refresh tokens.

- **Expense Management**
  - Add, update, and delete expenses.
  - Validate fields such as amount and category.
  - Support for custom expense categories.
  - Get all expenses for the logged-in user with optional filtering (by category, date range).

- **Summary Statistics**
  - Total expenses tracking.
  - Monthly breakdown of expenses.
  - Top 3 categories by spending.

- **Recurring Expenses**
  - Set recurring expenses with automatic generation.

- **Budgeting System**
  - Set monthly budgets and track usage.
  - Notification when budget limits are exceeded.

- **Export to CSV**
  - Download expenses as a CSV file.

- **Profile Management**
  - Update user profile information and change passwords.

## Technologies

- **Backend:** Flask
- **Database:** SQLite
- **Authentication:** JWT (JSON Web Tokens)
- **Email:** Flask-Mail (for password reset functionality)
- **CSV Export:** Built-in CSV module

## API Endpoints

### User Management

- **Register User**
  - `POST /register`
  - Request Body: 
    ```json
    {
      "username": "string",
      "email": "string",
      "password": "string"
    }
    ```
  - Response: 
    ```json
    {
      "message": "User registered successfully"
    }
    ```

- **Login User**
  - `POST /login`
  - Request Body:
    ```json
    {
      "email": "string",
      "password": "string"
    }
    ```
  - Response:
    ```json
    {
      "access_token": "string",
      "refresh_token": "string"
    }
    ```

- **Refresh Access Token**
  - `POST /refresh`
  - Requires JWT refresh token in the header.
  - Response:
    ```json
    {
      "access_token": "string"
    }
    ```

- **Reset Password Request**
  - `POST /reset_password_request`
  - Request Body:
    ```json
    {
      "email": "string"
    }
    ```
  - Response:
    ```json
    {
      "message": "Password reset email sent"
    }
    ```

- **Reset Password**
  - `POST /reset_password/<token>`
  - Request Body:
    ```json
    {
      "password": "string"
    }
    ```
  - Response:
    ```json
    {
      "message": "Password has been reset"
    }
    ```

### Expense Management

- **Add Expense**
  - `POST /expenses`
  - Request Body:
    ```json
    {
      "amount": float,
      "category_id": int,
      "date": "YYYY-MM-DD",
      "payment_method": "string",
      "description": "string (optional)",
      "recurrence_type": "string (optional)",
      "recurrence_interval": int (optional)
    }
    ```
  - Response:
    ```json
    {
      "message": "Expense added successfully"
    }
    ```

- **Get All Expenses**
  - `GET /expenses`
  - Response:
    ```json
    [
      {
        "id": int,
        "amount": float,
        "category": "string",
        "description": "string",
        "date": "YYYY-MM-DD",
        "payment_method": "string"
      }
    ]
    ```

- **Filter Expenses**
  - `GET /expenses/filter`
  - Query Parameters: `category_name`, `start_date`, `end_date`
  - Response: Similar to "Get All Expenses"

- **Get Expense Summary**
  - `GET /expenses/summary`
  - Response:
    ```json
    {
      "total_expenses": float,
      "monthly_breakdown": [
        {
          "month": "YYYY-MM",
          "total_amount": float
        }
      ],
      "top_categories": [
        {
          "category": "string",
          "total_amount": float
        }
      ]
    }
    ```

- **Update Expense**
  - `PUT /expenses/<int:expense_id>`
  - Request Body: Similar to "Add Expense" (optional fields)
  - Response:
    ```json
    {
      "message": "Expense updated successfully."
    }
    ```

- **Delete Expense**
  - `DELETE /expenses/<int:expense_id>`
  - Response:
    ```json
    {
      "message": "Expense deleted successfully."
    }
    ```

### Category Management

- **Add Category**
  - `POST /categories`
  - Request Body:
    ```json
    {
      "name": "string"
    }
    ```
  - Response:
    ```json
    {
      "message": "Category created successfully",
      "category_id": int
    }
    ```
