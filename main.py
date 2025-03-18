from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Модель користувача
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Логін
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Створення форми входу
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return 'Невірний логін або пароль'
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return 'Вітаємо в адмінці!'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Створення адміністратора вручну
def create_admin():
    with app.app_context():
        db.create_all()  # Створення всіх таблиць
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin')
            admin.set_password('adminpassword')  # паролем користувача буде 'adminpassword'
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    create_admin()  # Викликаємо функцію створення адміністратора перед запуском
    app.run(debug=True)
