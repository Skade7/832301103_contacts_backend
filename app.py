from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, TelField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///address_book.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# === 上传配置 ===
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB 限制
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# 工具函数
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# === 数据库模型 ===
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    avatar = db.Column(db.String(200), default='default.png')  # 新增头像字段
    contacts = db.relationship('Contact', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100))
    address = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# === 表单定义 ===
class RegistrationForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(min=4, max=50)])
    email = EmailField('邮箱', validators=[DataRequired(), Email()])
    password = PasswordField('密码', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('确认密码', validators=[
        DataRequired(), EqualTo('password', message='两次密码不一致')
    ])
    submit = SubmitField('注册')


class LoginForm(FlaskForm):
    email = EmailField('邮箱', validators=[DataRequired(), Email()])
    password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('登录')


class ContactForm(FlaskForm):
    name = StringField('姓名', validators=[DataRequired()])
    phone = TelField('电话', validators=[DataRequired()])
    email = EmailField('邮箱')
    address = StringField('地址')
    submit = SubmitField('保存')


# === 登录管理 ===
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# === 路由 ===
@app.route('/')
@login_required
def index():
    search_query = request.args.get('search', '')
    if search_query:
        contacts = Contact.query.filter(
            Contact.owner == current_user,
            (Contact.name.contains(search_query) | Contact.phone.contains(search_query))
        ).all()
    else:
        contacts = Contact.query.filter_by(owner=current_user).all()
    return render_template('index.html', contacts=contacts, form=ContactForm())


@app.route('/add_contact', methods=['POST'])
@login_required
def add_contact():
    form = ContactForm()
    if form.validate_on_submit():
        new_contact = Contact(
            name=form.name.data,
            phone=form.phone.data,
            email=form.email.data,
            address=form.address.data,
            owner=current_user
        )
        db.session.add(new_contact)
        db.session.commit()
        flash('联系人添加成功！', 'success')
    return redirect(url_for('index'))


@app.route('/edit_contact/<int:contact_id>', methods=['GET', 'POST'])
@login_required
def edit_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    if contact.owner != current_user:
        flash('无权限操作此联系人', 'danger')
        return redirect(url_for('index'))

    form = ContactForm(obj=contact)
    if form.validate_on_submit():
        contact.name = form.name.data
        contact.phone = form.phone.data
        contact.email = form.email.data
        contact.address = form.address.data
        db.session.commit()
        flash('联系人更新成功！', 'success')
        return redirect(url_for('index'))
    return render_template('index.html', edit_form=form, edit_id=contact_id,
                           contacts=Contact.query.filter_by(owner=current_user).all())


@app.route('/delete_contact/<int:contact_id>')
@login_required
def delete_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    if contact.owner == current_user:
        db.session.delete(contact)
        db.session.commit()
        flash('联系人已删除', 'success')
    else:
        flash('无权限操作此联系人', 'danger')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('用户名已存在', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=form.email.data).first():
            flash('邮箱已被注册', 'danger')
            return redirect(url_for('register'))
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('邮箱或密码错误', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# === 上传头像功能 ===
@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('未选择文件', 'danger')
        return redirect(url_for('index'))
    file = request.files['avatar']
    if file.filename == '':
        flash('未选择文件', 'danger')
        return redirect(url_for('index'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filename = f"user_{current_user.id}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        if current_user.avatar != 'default.png':
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.avatar)
            if os.path.exists(old_path):
                os.remove(old_path)
        current_user.avatar = filename
        db.session.commit()
        flash('头像上传成功！', 'success')
    else:
        flash('文件类型不支持，请上传png/jpg/jpeg/gif格式图片', 'danger')
    return redirect(url_for('index'))


# 初始化数据库
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
