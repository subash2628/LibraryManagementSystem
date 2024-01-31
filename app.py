from flask import Flask, request, jsonify, render_template,request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
#from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
#from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user,login_required, current_user
from datetime import date

import hashlib


app = Flask(__name__)

@app.route('/')
def home():
    return render_template("home.html")

# Configure the database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:changeme@localhost/library_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'yKk2&6jRr9$B!pQ'
#app.config["SECRET_KEY"] = "abc"

# Initialize SQLAlchemy
db = SQLAlchemy(app)
#jwt = JWTManager(app)

# LoginManager is needed for our application 
# to be able to log in and out users
login_manager = LoginManager()
login_manager.init_app(app)

with app.app_context():
    try:
        db.engine.connect()
        print("Successfully connected to the database.")
    except Exception as e:
        print(f"Failed to connect to the database. Error: {e}")



# Define User model
class User(UserMixin, db.Model):
    def get_id(self):
           return (self.UserID)

    UserID = db.Column(db.String(255), primary_key=True)
    Name = db.Column(db.String(255), nullable=False)
    Email = db.Column(db.String(255), nullable=False, unique=True)
    MembershipDate = db.Column(db.Date, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    # Relationship with BorrowedBooks
    borrowed_books = db.relationship('BorrowedBooks', backref='user', lazy=True)


# Define Book model
class Book(db.Model):
    BookID = db.Column(db.Integer, primary_key=True)
    Title = db.Column(db.String(255), nullable=False)
    ISBN = db.Column(db.String(20), nullable=False, unique=True)
    PublishedDate = db.Column(db.Date, nullable=False)
    Genre = db.Column(db.String(50), nullable=False)
    # Relationship with BookDetails (1-1)
    details = db.relationship('BookDetails', backref='book', uselist=False, lazy=True)
    # Relationship with BorrowedBooks
    borrowed_books = db.relationship('BorrowedBooks', backref='book', lazy=True)


# Define BookDetails model
class BookDetails(db.Model):
    DetailsID = db.Column(db.Integer, primary_key=True)
    BookID = db.Column(db.Integer, db.ForeignKey('book.BookID'), nullable=False, unique=True)
    NumberOfPages = db.Column(db.Integer, nullable=False)
    Publisher = db.Column(db.String(255), nullable=False)
    Language = db.Column(db.String(50), nullable=False)


# Define BorrowedBooks model
class BorrowedBooks(db.Model):
    UserID = db.Column(db.String(255), db.ForeignKey('user.UserID'), primary_key=True)
    BookID = db.Column(db.Integer, db.ForeignKey('book.BookID'), primary_key=True)
    BorrowDate = db.Column(db.Date, nullable=False)
    ReturnDate = db.Column(db.Date)

def generate_user_id(name, email, password):
    # Concatenate name, email, and password
    data_to_hash = f'{name}{email}{password}'.encode('utf-8')
    # Use SHA-256 hash function
    hashed_data = hashlib.sha256(data_to_hash).hexdigest()
    # Take the first 8 characters of the hash as the user ID
    user_id = hashed_data[:8]
    return user_id

def generate_book_id(Title, ISBN, PublishedDate):
    data_to_hash = f'{Title}{ISBN}{PublishedDate}'.encode('utf-8')
    # Use SHA-256 hash function
    hashed_data = hashlib.sha256(data_to_hash).hexdigest()
    # Take the first 8 characters of the hash as the user ID
    book_id = hashed_data[:8]
    return book_id

def generate_details_id(BookID, Publisher, Language):
    data_to_hash = f'{BookID}{Publisher}{Language}'.encode('utf-8')
    # Use SHA-256 hash function
    hashed_data = hashlib.sha256(data_to_hash).hexdigest()
    # Take the first 8 characters of the hash as the user ID
    details_id = hashed_data[:8]
    return details_id




# Creates a user loader callback that returns the user object given an id
@login_manager.user_loader
def loader_user(user_id):
	return User.query.get(user_id)


# User APIs
@app.route('/users', methods=['GET','POST'])
def create_user():
    try:
        if request.method == "POST":
            #data = request.get_json()
            #hashed_password = generate_password_hash(data['Password'], method='pbkdf2:sha1')

            UserName = request.form.get("username")
            Password = request.form.get("password")
            Email = request.form.get("email")

            user_id = generate_user_id(UserName, Password, Email)

            #check is user already exists
            user = User.query.get(user_id)
            if user: return jsonify({'error': 'User Already Exist', 'status_code': 404}), 404

            new_user = User(UserID=user_id, Name=UserName, Email=Email, MembershipDate=date.today(), password=Password)
        
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': 'User created successfully'}), 201

        return render_template("sign_up.html")

    except Exception as e:
        return jsonify(str(e)), 500
    


@app.route('/users/all', methods=['GET'])
@login_required
def list_all_users():
    users = User.query.all()
    users_list = [{'UserID': user.UserID, 'Name': user.Name, 'Email': user.Email, 'MembershipDate': user.MembershipDate}
                  for user in users]
    return jsonify(users_list)


@app.route('/users/<user_id>', methods=['GET'])
@login_required
def get_user_by_id(user_id):
    user = User.query.get(user_id)
    if user:
        user_data = {'UserID': user.UserID, 'Name': user.Name, 'Email': user.Email, 'MembershipDate': user.MembershipDate}
        return jsonify(user_data)
    return jsonify({'error': 'User not found', 'status_code': 404}), 404


# Book APIs
@app.route('/books', methods=['POST'])
@login_required
def add_new_book():
    try:
        #data = request.get_json()

        Title = request.form.get("title")
        ISBN = request.form.get("isbn")
        PublishedDate = request.form.get("published_date")
        Genre = request.form.get("genre")

        book_id = generate_book_id(Title, ISBN, PublishedDate)
        book = Book.query.get(book_id)

        if not book:
            new_book = Book(BookID=book_id,Title=Title, ISBN=ISBN, PublishedDate=PublishedDate, Genre=Genre)
            db.session.add(new_book)
            db.session.commit()
            return jsonify({'message': 'Book created successfully'}), 201

        return jsonify({'error': 'Book Already Exists', 'status_code': 404}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/books', methods=['GET'])
@login_required
def list_all_books():
    books = Book.query.all()
    books_list = [{'BookID': book.BookID, 'Title': book.Title, 'ISBN': book.ISBN,
                   'PublishedDate': book.PublishedDate, 'Genre': book.Genre} for book in books]
    return jsonify(books_list)


@app.route('/books/<book_id>', methods=['GET'])
@login_required
def get_book_by_id(book_id):
    book = Book.query.get(book_id)
    if book:
        book_data = {'BookID': book.BookID, 'Title': book.Title, 'ISBN': book.ISBN,
                     'PublishedDate': book.PublishedDate, 'Genre': book.Genre}
        return jsonify(book_data)
    return jsonify({'error': 'Book not found', 'status_code': 404}), 404


@app.route('/books/<book_id>/details', methods=['POST', 'PUT'])
@login_required
def assign_update_book_details(book_id):
    try:
        data = request.get_json()
        book = Book.query.get(book_id)
        #print(book)
        
        if book:
            details = BookDetails.query.filter_by(BookID=book_id).first()
            #details = BookDetails.query.filter_by(BookID=book_id)
            #print("details: ", type(details))
            if not details:
                details_id = generate_details_id(book_id, data['Publisher'], data['Language'])
                details = BookDetails(DetailsID=details_id ,BookID=book_id, NumberOfPages=data['NumberOfPages'],
                                    Publisher=data['Publisher'], Language=data['Language'])
                db.session.add(details)
            else:
                details.NumberOfPages = data['NumberOfPages']
                details.Publisher = data['Publisher']
                details.Language = data['Language']
            db.session.commit()
            return jsonify({'message': 'Book details assigned/updated successfully'}), 200
        return jsonify({'error': 'Book not found', 'status_code': 404}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# BorrowedBooks APIs
@app.route('/borrow', methods=['POST'])
@login_required
def borrow_book():
    #print("current user  ",current_user.UserID)
    try:
        data = request.get_json()
        book_id = data['BookID']
        user_id = current_user.UserID

        book = Book.query.get(book_id)
        
        alreadyBorrowed = BorrowedBooks.query.filter_by(BookID=book_id).first()

        if book and not alreadyBorrowed :
            borrowed_book = BorrowedBooks(UserID=user_id, BookID=book_id, BorrowDate=date.today(),ReturnDate=data['ReturnDate'])
            db.session.add(borrowed_book)
            db.session.commit()
            return jsonify({'message': 'Book borrowed successfully'}), 201

        return jsonify({'error': 'User or Book not found', 'status_code': 404}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/return/<book_id>', methods=['PUT'])
@login_required
def return_book(book_id):
    try:
        #data = request.get_json()

        #user_id = data['UserID']
        #return_date = data['ReturnDate']

        book = Book.query.get(book_id)
        user = User.query.get(current_user.UserID)

        if not user: return jsonify({'error': 'User not found', 'status_code': 404}), 404
        if not book: return jsonify({'error': 'book not found', 'status_code': 404}), 404

        borrowed_book = BorrowedBooks.query.filter_by(UserID=current_user.UserID, BookID=book_id).first()

        if borrowed_book:
            #borrowed_book.ReturnDate = return_date
            db.session.delete(borrowed_book)
            db.session.commit()
            return jsonify({'message': 'Book returned successfully'}), 200

        return jsonify({'error': 'Borrowed book not found', 'status_code': 404}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/borrowed-books/<user_id>', methods=['GET'])
@login_required
def list_all_borrowed_books(user_id):
    
    user = User.query.get(user_id)
    #book = Book.query.get(book_id)

    if not user: return jsonify({'error': 'User not found', 'status_code': 404}), 404

    borrowed_books_list = BorrowedBooks.query.filter_by(UserID=user_id).all()
    #print("borrowed_books_list ", len(borrowed_books_list))

    if len(borrowed_books_list)==0: return jsonify({'message': 'No Books Borrowed by this user', 'status_code': 200}), 200

    borrowed_books_data = [{'UserID': borrowed_book.UserID, 'BookID': borrowed_book.BookID,
                            'BorrowDate': borrowed_book.BorrowDate, 'ReturnDate': borrowed_book.ReturnDate}
                           for borrowed_book in borrowed_books_list]
    return jsonify(borrowed_books_data)


# Authentication API
@app.route('/login', methods=['GET','POST'])
def login():
    try:
        if request.method == "POST":
            UserEmail = request.form.get("email")
            Password = request.form.get("password")
            print("form data: ", UserEmail, Password)

            user = User.query.filter_by(Email=UserEmail).first()
            #User.query.get(user_id)
            # if user and check_password_hash(user.password, data['Password']):
            print("print: ",type(user), Password )
            
            if user and (user.password == Password):
                login_user(user)
                return redirect(url_for("home"))
            
            return jsonify({'message': 'Invalid credentials, Go Back to try again!'}), 401
            
        return render_template("login.html")

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == '__main__':
    # Create the database tables before running the app
    db.create_all()
    app.run(debug=True)
