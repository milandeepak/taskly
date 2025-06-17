import os
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, session, redirect, url_for , flash, render_template, request
import uuid
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
uri = os.getenv('DATABASE_URL')
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


#User Model 

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username =  db.Column(db.String(150), unique=True, nullable =False)
    password_hash = db.Column(db.Text, nullable=False)


    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('tasks', lazy=True))

    
with app.app_context():
    db.create_all()

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    if current_user.is_authenticated:
        user_tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.created_at).all()
        return render_template('home.html', tasks=user_tasks, logged_in=True)
    else:
        # Load session tasks or set dummy tasks
        if 'tasks' not in session:
            session['tasks'] = [
                {'id': str(uuid.uuid4()), 'title': "Try the app!", 'description': "You can add, edit, and delete tasks."},
                {'id': str(uuid.uuid4()), 'title': "Add a new task.", 'description': "Click the button to add a new task."},
                {'id': str(uuid.uuid4()), 'title': "Edit this one.", 'description': "Click the edit button to modify this task."},
                {'id': str(uuid.uuid4()), 'title': "Delete a task.", 'description': "Click the delete button to remove this task."},
            ]
        flash('Welcome to Taskly Demo! Feel free to explore the features. Sign up to save your tasks permanently!')
        return render_template('demo.html', tasks=session['tasks'], logged_in=False)


@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    if request.method =="POST":
        username = request.form['username']
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
        else:
            new_user =  User(username=username, password_hash= generate_password_hash(password))    
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful! You can now log in.')
            return redirect(url_for('login'))
        
    return render_template('signup.html')    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!')
            return redirect(url_for('home'))

        if user is None:
            flash('User not found. Please sign up.')
            return redirect(url_for('signup'))

        flash('Invalid username or password.')
        
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('home'))

@app.route('/add', methods=['POST'])
@login_required
def add_task():
    title = request.form['title']
    description = request.form.get('description', '')
    new_task = Task(title=title, description=description, user_id=current_user.id)
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('home'))

    
@app.route('/delete/<int:task_id>', methods=['POST', 'GET'])
@login_required
def delete_task(task_id):
        task = Task.query.get_or_404(task_id)
        if task.user_id != current_user.id:
            flash("Unauthorized")
            return redirect(url_for('home'))
        db.session.delete(task)
        db.session.commit()
        return redirect(url_for('home'))

@app.route('/edit/<int:task_id>', methods=['POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash("Unauthorized")
        return redirect(url_for('home'))

    task.title = request.form['title']
    task.description = request.form['description']
    db.session.commit()
    flash("Task updated successfully")
    return redirect(url_for('home'))


# ===========================
    # Demo Routes
# ===========================

@app.route('/demo/add', methods=['POST'])
def demo_add_task():
    title = request.form['title']
    description = request.form.get('description', '')
    new_task = {
        'id': str(uuid.uuid4()),
        'title': title,
        'description': description
    }
    tasks = session.get('tasks', [])
    tasks.append(new_task)
    session['tasks'] = tasks
    flash("Task added!")
    return redirect(url_for('home'))

@app.route('/demo/edit/<task_id>', methods=['POST'])
def demo_edit_task(task_id):
    tasks = session.get('tasks', [])
    for task in tasks:
        if task['id'] == task_id:
            task['title'] = request.form['title']
            task['description'] = request.form['description']
            break
    session['tasks'] = tasks
    flash("Task updated.")
    return redirect(url_for('home'))

@app.route('/demo/delete/<task_id>', methods=['POST'])
def demo_delete_task(task_id):
    tasks = session.get('tasks', [])
    tasks = [task for task in tasks if task['id'] != task_id]
    session['tasks'] = tasks
    flash("Task deleted.")
    return redirect(url_for('home'))





if __name__ == '__main__':
    app.run(debug=True)
