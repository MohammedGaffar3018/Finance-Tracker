from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from models import db, User, Transaction, Budget
import os
from datetime import datetime
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here') # Use env var for secret key
# Use the provided DATABASE_URL or fallback to SQLite
# In production (Vercel), DATABASE_URL will be set automatically
uri = os.environ.get('DATABASE_URL', 'sqlite:///finance.db')
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')

# Google OAuth Configuration
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
oauth = OAuth(app)

google = None
if app.config['GOOGLE_CLIENT_ID'] and app.config['GOOGLE_CLIENT_SECRET']:
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        access_token_url='https://accounts.google.com/o/oauth2/token',
        access_token_params=None,
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params=None,
        api_base_url='https://www.googleapis.com/oauth2/v1/',
        userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
        client_kwargs={'scope': 'openid email profile'},
    )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).limit(5).all()
    
    # Calculate totals
    all_transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    total_income = sum(t.amount for t in all_transactions if t.type == 'income')
    total_expense = sum(t.amount for t in all_transactions if t.type == 'expense')
    balance = total_income - total_expense
    
    return render_template('index.html', transactions=transactions, total_income=total_income, total_expense=total_expense, balance=balance, user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('auth.html', mode='login')

@app.route('/login/google')
def google_login():
    if not google:
        flash('Google Login is not configured.', 'danger')
        return redirect(url_for('login'))
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/callback')
def google_authorize():
    if not google:
        flash('Google Login is not configured.', 'danger')
        return redirect(url_for('login'))
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    email = user_info['email']
    
    user = User.query.filter_by(email=email).first()
    if not user:
        # Create user if not exists (auto-verified via Google)
        user = User(username=user_info['name'], email=email, password='google_oauth_user', is_verified=True)
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    return redirect(url_for('index'))

@app.route('/verify_email/<token>')
def verify_email(token):
    # In a real app, you'd decode the token to get the email
    # For simplicity, we'll just show a message
    flash('Email verified successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        
        # Send Verification Email (Commented out until credentials are set)
        # msg = Message('Verify your email', sender='noreply@financetracker.com', recipients=[email])
        # msg.body = f'Click here to verify: {url_for("verify_email", token="dummy_token", _external=True)}'
        # mail.send(msg)
        
        flash('Your account has been created! Please verify your email.', 'success')
        return redirect(url_for('login'))
    return render_template('auth.html', mode='register')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_transaction', methods=['POST'])
@login_required
def add_transaction():
    amount = float(request.form.get('amount'))
    category = request.form.get('category')
    type = request.form.get('type')
    description = request.form.get('description')
    date_str = request.form.get('date')
    
    if date_str:
        date = datetime.strptime(date_str, '%Y-%m-%d')
    else:
        date = datetime.utcnow()

    transaction = Transaction(amount=amount, category=category, type=type, description=description, date=date, user_id=current_user.id)
    db.session.add(transaction)
    db.session.commit()
    flash('Transaction added!', 'success')
    return redirect(url_for('index'))

@app.route('/delete_transaction/<int:id>')
@login_required
def delete_transaction(id):
    transaction = Transaction.query.get_or_404(id)
    if transaction.user_id == current_user.id:
        db.session.delete(transaction)
        db.session.commit()
        flash('Transaction deleted!', 'success')
    return redirect(url_for('index'))

@app.route('/api/data')
@login_required
def get_data():
    # Helper for charts
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    
    # Income vs Expense
    income = sum(t.amount for t in transactions if t.type == 'income')
    expense = sum(t.amount for t in transactions if t.type == 'expense')
    
    # Category breakdown (Expense only for now)
    categories = {}
    for t in transactions:
        if t.type == 'expense':
            categories[t.category] = categories.get(t.category, 0) + t.amount
            
    return jsonify({
        'income': income,
        'expense': expense,
        'categories': list(categories.keys()),
        'category_data': list(categories.values())
    })

@app.route('/budget', methods=['GET', 'POST'])
@login_required
def budget():
    if request.method == 'POST':
        category = request.form.get('category')
        amount = float(request.form.get('amount'))
        month = datetime.utcnow().strftime('%Y-%m') # Current month for simplicity
        
        # Check if budget exists for this category/month
        existing_budget = Budget.query.filter_by(user_id=current_user.id, category=category, month=month).first()
        if existing_budget:
            existing_budget.amount = amount
            flash('Budget updated!', 'success')
        else:
            new_budget = Budget(category=category, amount=amount, month=month, user_id=current_user.id)
            db.session.add(new_budget)
            flash('Budget set!', 'success')
        db.session.commit()
        return redirect(url_for('budget'))
        
    budgets = Budget.query.filter_by(user_id=current_user.id).all()
    
    # Calculate spending per category to show progress
    spending = {}
    transactions = Transaction.query.filter_by(user_id=current_user.id, type='expense').all()
    for t in transactions:
        spending[t.category] = spending.get(t.category, 0) + t.amount
        
    return render_template('budget.html', budgets=budgets, spending=spending)

@app.route('/delete_budget/<int:id>')
@login_required
def delete_budget(id):
    budget = Budget.query.get_or_404(id)
    if budget.user_id == current_user.id:
        db.session.delete(budget)
        db.session.commit()
        flash('Budget deleted!', 'success')
    return redirect(url_for('budget'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
