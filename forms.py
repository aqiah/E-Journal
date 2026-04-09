from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Regexp

# Task 1: Secure Registration Form
class RegistrationForm(FlaskForm):
    # Regex ensures only letters, numbers, or underscores to prevent script injection [cite: 11]
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=2, max=20),
        Regexp('^[A-Za-z0-9_]+$', message="Username must contain only letters, numbers, or underscores")
    ])
    # Plain text passwords will be hashed in the route before saving [cite: 57]
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    submit = SubmitField('Sign Up')

# Task 1: Secure Login Form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Task 1: Secure Journal Entry Form
class JournalForm(FlaskForm):
    # Validating length and data presence to prevent malformed data [cite: 3, 138]
    title = StringField('Title', validators=[
        DataRequired(), 
        Length(max=100)
    ])
    content = TextAreaField('Content', validators=[
        DataRequired()
    ])
    submit = SubmitField('Save Memory')