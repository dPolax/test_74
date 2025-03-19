# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps


app = Flask(__name__)  
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Моделі
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Декоратор для перевірки адміністратора
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Доступ заборонено. Потрібні права адміністратора.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Маршрути
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        user_exists = User.query.filter_by(username=username).first() is not None
        email_exists = User.query.filter_by(email=email).first() is not None
        
        if user_exists:
            flash('Користувач з таким ім\'ям вже існує', 'danger')
            return redirect(url_for('register'))
        
        if email_exists:
            flash('Користувач з такою поштою вже існує', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Реєстрація успішна! Тепер ви можете увійти.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    # Перевірка на перший запуск (чи є адміністратори)
    admin_exists = User.query.filter_by(is_admin=True).first() is not None
    first_run = not admin_exists
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Ви успішно увійшли!', 'success')
            
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Невірне ім\'я користувача або пароль', 'danger')
    
    return render_template('login.html', first_run=first_run)

@app.route('/setup_admin', methods=['GET', 'POST'])
def setup_admin():
    # Перевірка на перший запуск (чи є адміністратори)
    admin_exists = User.query.filter_by(is_admin=True).first() is not None
    
    if admin_exists:
        flash('Адміністратор вже налаштований', 'warning')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        hashed_password = generate_password_hash(password)
        admin_user = User(username=username, email=email, password=hashed_password, is_admin=True)
        
        db.session.add(admin_user)
        db.session.commit()
        
        flash('Адміністратор успішно налаштований!', 'success')
        return redirect(url_for('login'))
    
    return render_template('setup_admin.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Ви вийшли з системи', 'success')
    return redirect(url_for('home'))

@app.route('/admin/')
@login_required
@admin_required
def admin_panel():
    users = User.query.all()
    return render_template('admin/dashboard.html', users=users)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/delete/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Ви не можете видалити себе', 'danger')
        return redirect(url_for('admin_users'))
    
    db.session.delete(user)
    db.session.commit()
    
    flash('Користувач успішно видалений', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/toggle_admin/<int:user_id>')
@login_required
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Ви не можете змінити свої права', 'danger')
    else:
        user.is_admin = not user.is_admin
        db.session.commit()
        status = 'адміністратор' if user.is_admin else 'користувач'
        flash(f'Статус користувача змінено на {status}', 'success')
    
    return redirect(url_for('admin_users'))
#1
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
