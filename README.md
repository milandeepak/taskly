# Taskly - Task Management Application

Taskly is a modern, user-friendly task management web application built with Flask. It allows users to create, manage, and organize their tasks efficiently with a clean and intuitive interface.

## Features

### User Management
- User registration and authentication
- Secure password hashing
- User-specific task management
- Session-based guest mode for demo users

### Task Management
- Create new tasks with title and description
- Edit existing tasks
- Delete tasks
- Mark tasks as completed
- Automatic timestamp tracking for task creation
- Task organization by user

### Security Features
- Secure password storage using Werkzeug's password hashing
- Protected routes with login requirements
- User-specific task access control
- Session management for guest users

### User Experience
- Responsive web interface
- Flash messages for user feedback
- Intuitive navigation
- Demo mode for non-registered users

## Technical Stack

- **Backend Framework**: Flask
- **Database**: PostgreSQL (with SQLAlchemy ORM)
- **Authentication**: Flask-Login
- **Security**: Werkzeug Security
- **Environment Variables**: python-dotenv

## Setup Instructions

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set up environment variables:
   - Create a `.env` file
   - Add the following variables:
     ```
     SECRET_KEY=your_secret_key
     DATABASE_URL=your_database_url
     ```
5. Initialize the database:
   ```bash
   flask db init
   flask db migrate
   flask db upgrade
   ```
6. Run the application:
   ```bash
   python app.py
   ```

## Usage

1. Visit the homepage to see the demo mode
2. Sign up for a new account or log in
3. Start managing your tasks:
   - Add new tasks using the "Add Task" button
   - Edit tasks by clicking the edit icon
   - Delete tasks using the delete button
   - Mark tasks as complete

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
