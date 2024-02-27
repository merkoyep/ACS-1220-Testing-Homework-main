import os
from unittest import TestCase

from datetime import date
 
from books_app.extensions import app, db, bcrypt
from books_app.models import Book, Author, User, Audience

"""
Run these tests with the command:
python -m unittest books_app.main.tests
"""

#################################################
# Setup
#################################################

def create_books():
    a1 = Author(name='Harper Lee')
    b1 = Book(
        title='To Kill a Mockingbird',
        publish_date=date(1960, 7, 11),
        author=a1
    )
    db.session.add(b1)

    a2 = Author(name='Sylvia Plath')
    b2 = Book(title='The Bell Jar', author=a2)
    db.session.add(b2)
    db.session.commit()

def create_user():
    password_hash = bcrypt.generate_password_hash('password').decode('utf-8')
    user = User(username='me1', password=password_hash)
    db.session.add(user)
    db.session.commit()

#################################################
# Tests
#################################################

class AuthTests(TestCase):
    """Tests for authentication (login & signup)."""
 
    def setUp(self):
        """Executed prior to each test."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        db.drop_all()
        db.create_all()

    def test_signup(self):
        # Write a test for the signup route. It should:
        # - Make a POST request to /signup, sending a username & password
        # - Check that the user now exists in the database
        form_data = {
            'username': 'taylorswift',
            'password': 'testpassword'
        }
        res = app.test_client().post('/signup', data=form_data)
        self.assertEqual(res.status_code, 302)

        user = User.query.filter_by(username=form_data['username']).first()
        self.assertEqual(user.username, 'taylorswift')
        

    def test_signup_existing_user(self):
        # TODO: Write a test for the signup route. It should:
        # - Create a user
        # - Make a POST request to /signup, sending the same username & password
        # - Check that the form is displayed again with an error message
        existing_user = User(username='taylorswift', password='testpassword')
        db.session.add(existing_user)
        db.session.commit()
        form_data = {
            'username': 'taylorswift',
            'password': 'testpassword'
        }
        res = app.test_client().post('/signup', data=form_data)
        self.assertEqual(res.status_code, 200)
        self.assertIn('That username is taken. Please choose a different one.', res.data.decode('utf-8'))

    def test_login_correct_password(self):
        # Write a test for the login route. It should:
        # - Create a user
        # - Make a POST request to /login, sending the created username & password
        # - Check that the "login" button is not displayed on the homepage
        form_data = {
            'username': 'michaelscott',
            'password': 'paper'
        }
        res = app.test_client().post('/signup', data=form_data)
        self.assertEqual(res.status_code, 302)
        self.assertNotIn('<a href="/login">Log In</a>', res.data.decode('utf-8'))

    def test_login_nonexistent_user(self):
        # TODO: Write a test for the login route. It should:
        # - Make a POST request to /login, sending a username & password
        # - Check that the login form is displayed again, with an appropriate
        #   error message
        form_data = {
            'username': 'totallyauser',
            'password': 'sceretlynotauser'
        }
        res = app.test_client().post('/login', data=form_data)
        self.assertEqual(res.status_code, 200)
        self.assertIn('No user with that username. Please try again.', res.data.decode('utf-8'))


    def test_login_incorrect_password(self):
        # TODO: Write a test for the login route. It should:
        # - Create a user
        # - Make a POST request to /login, sending the created username &
        #   an incorrect password
        # - Check that the login form is displayed again, with an appropriate
        #   error message
        hashed_password = bcrypt.generate_password_hash('password1').decode('utf-8')
        existing_user = User(username='taylorswift', password=hashed_password)
        db.session.add(existing_user)
        db.session.commit()
        form_data = {
            'username': 'taylorswift',
            'password': 'password34'
        }
        res = app.test_client().post('/login', data=form_data)
        self.assertEqual(res.status_code, 200)
        self.assertIn('Password doesn&#39;t match. Please try again', res.data.decode('utf-8'))


    def test_logout(self):
        # TODO: Write a test for the logout route. It should:
        # - Create a user
        # - Log the user in (make a POST request to /login)
        # - Make a GET request to /logout
        # - Check that the "login" button appears on the homepage
        hashed_password = bcrypt.generate_password_hash('password1').decode('utf-8')
        existing_user = User(username='taylorswift', password=hashed_password)
        db.session.add(existing_user)
        db.session.commit()
        form_data = {
            'username': 'taylorswift',
            'password': hashed_password
        }
        app.test_client().post('/login', data=form_data)
        res = app.test_client().get('/logout', follow_redirects=True)
        self.assertIn('<a href="/login">Log In</a>', res.data.decode('utf-8'))

