### Конспект урока с кодом:

1. **План урока**:
   - Разработка небольшого проекта с использованием изученных технологий.
   - Публикация сайта на хостинге.

2. **Создание структуры проекта**:
   - Создать пакет `app`, в котором будут файлы: `models.py`, `routes.py`, `forms.py`.
   - Создать папку `templates` и добавить HTML-файлы: `base.html`, `index.html`, `login.html`, `register.html`.

3. **Настройка файла `__init__.py`**:
```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

from app import routes
```

4. **Создание базы данных в `models.py`**:
```python
from app import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    clicks = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'User({self.username}) - clicks: {self.clicks}'
```

5. **Форма регистрации в `forms.py`**:
```python
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from app.models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Такое имя уже существует.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Такая почта уже используется.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Запомни меня')
    submit = SubmitField('Login')
```

6. **Настройка маршрутов в `routes.py`**:
```python
from flask import render_template, request, redirect, url_for, flash
from app import app, db, bcrypt
from app.models import User
from app.forms import LoginForm, RegistrationForm
from flask_login import login_user, logout_user, current_user, login_required

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Вы успешно зарегистрировались!', 'success')
        return redirect(url_for('login'))
    return render_template("register.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Неверно введены данные аккаунта', 'danger')
    return render_template("login.html", form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/click')
@login_required
def click():
    current_user.clicks += 1
    db.session.commit()
    return redirect(url_for('index'))
```

7. **Настройка шаблонов HTML**:

- **`base.html`**:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>

<nav>
    <a href="{{ url_for('index') }}">Игра</a>
    {% if current_user.is_authenticated %}
        <a href="{{ url_for('logout') }}">Выход из аккаунта</a>
    {% else %}
        <a href="{{ url_for('login') }}">Вход в аккаунт</a>
        <a href="{{ url_for('register') }}">Регистрация</a>
    {% endif %}
</nav>

<div>
    {% with messages = get_flashed_messages(with_categories=True) %}
        {% if messages %}
            {% for category, message in messages %}
                <div>{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}
    
    {% block content %}
    {% endblock %}
</div>

</body>
</html>
```

- **`index.html`**:
```html
{% extends 'base.html' %}
{% block content %}
    <h1>Кликер!</h1>
    <p>Количество кликов - {{ current_user.clicks }}</p>
    <a href="{{ url_for('click') }}">Кнопка</a>
{% endblock %}
```

- **`login.html`**:
```html
{% extends 'base.html' %}
{% block content %}
    <h1>Вход</h1>
    <form method="post" action="{{ url_for('login') }}">
        {{ form.hidden_tag() }}
        <div>
            {{ form.email.label }}
            {{ form.email }}
        </div>
        <div>
            {{ form.password.label }}
            {{ form.password }}
        </div>
        <div>
            {{ form.submit }}
        </div>
    </form>
{% endblock %}
```

- **`register.html`**:
```html
{% extends 'base.html' %}
{% block content %}
    <h1>Регистрация</h1>
    <form method="post" action="{{ url_for('register') }}">
        {{ form.hidden_tag() }}
        <div>
            {{ form.username.label }}
            {{ form.username }}
        </div>
        <div>
            {{ form.password.label }}
            {{ form.password }}
        </div>
        <div>
            {{ form.confirm_password.label }}
            {{ form.confirm_password }}
        </div>
        <div>
            {{ form.submit }}
        </div>
    </form>
{% endblock %}
```

8. **Настройка файла `main.py`**:
```python
from app import app, db
from app.models import User

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
```

### 9. **Развёртывание сайта на хостинге**:

- **PythonAnywhere**:
   - Зарегистрируйтесь на [pythonanywhere.com](https://www.pythonanywhere.com/).
   - Создайте веб-приложение, выбрав Flask и указав путь к файлу `main.py`.
   - Загружайте файлы через раздел **Files** и запустите приложение с помощью кнопки **Run**.
   - Обновляйте приложение через панель управления.

Этот проект охватывает основные элементы веб-приложения с аутентификацией, динамическим контентом и развёртыванием на хостинге.