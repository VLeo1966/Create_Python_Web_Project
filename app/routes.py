# Импортируем библиотеки и команды:
from Flask import render_template, request, redirect, url_for, flash
from app import app, db, bcrypt
from app.models import User
from app.forms import LoginForm, RegistrationForm
from flask_login import login_user, logout_user, current_user, login_required
# Создаём декоратор главной страницы:

@app.route('/')
@login_required
def index():
    return render_template('index.html')
# Создаём функцию регистрации:

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is.authenticated:
        return redirect(url_for('index.html'))
    form = RegistrationForm()
    if form.validate_on_submit()
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Вы успешно зарегистрировались!', 'success')
        return redirect(url_for('login'))
    return render_template("register.html", form=form)
4. Создаём функцию login:

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index.html'))
    form = LoginForm()
    if form.validate_on_submit()
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Неверно введены данные аккаунта', 'danger')
    return render_template("login.html", form=form)
# Создаём функцию для выхода из аккаунта:

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))
# Создаём функцию для увеличения количества кликов при клике на кнопку:

@app.route('/click')
@login_required
def click():
    current_user.clicks += 1
    db.session.commit()
    return redirect(url_for('index'))