# Finance Tracker

A finance tracking application built with Flask, providing user authentication, expense management, budgeting features, and more. This application allows users to register, log in, and manage their expenses effectively.

## Table of Contents

- [Features](#features)
- [Technologies](#technologies)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Contributing](#contributing)
- [License](#license)

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

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/finance-tracker.git
   cd finance-tracker
