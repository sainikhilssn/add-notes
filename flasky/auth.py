from flask import Blueprint,render_template,request,flash,redirect,url_for
from .models import User
from werkzeug.security import generate_password_hash,check_password_hash
from . import db
from flask_login import login_user,login_required,logout_user,current_user



'''to use current_user we inherit User  from Usermixin in models.py '''
'''adding auth routes to blueprint'''
auth = Blueprint('auth',__name__)

@auth.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email = email).first()
        if user:
            if check_password_hash(user.password,password):
                flash('logged in succesfully!',category = 'success')
                login_user(user,remember = True)
                return redirect(url_for('views.home'))
            else:
                flash('incorrect password',category= 'success')
        else:
            flash('email does not exits please sign up ',category='error')
            
    return render_template("auth/login.html",user = current_user)

@auth.route('/signup',methods=['GET','POST'])
def signup():
    if request.method == 'POST' :
        email = request.form.get('email')
        password1 = request.form.get('password')
        password2 = request.form.get('password1')

        user = User.query.filter_by(email=email).first()
        if user : 
            flash('email already exists, login please',category='error')
        elif len(email) < 4 :
            flash('email id is too short','error')
        elif len(password1) < 8  :
            flash('must be 8 character long','error')
        elif password1 != password2 :
            flash('confirm password again','error')
        else :
            ''' adding user to data base '''
            new_user = User(email=email,password = generate_password_hash(password1,method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user,remember = True)
            flash('succesfully account created ',category='success')
            return redirect(url_for('views.home'))
    return render_template("auth/signup.html",user = current_user)




@auth.route('/logout')
@login_required  
def logout():
    logout_user()
    return redirect(url_for('auth.login'))