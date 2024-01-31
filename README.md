Makesure mysql database is running in the machine.

Run this command in mysql :=> create database library_db

Edit App.py , line 18, as follows: 

    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:changeme@localhost/library_db'

    replace the root and changeme with your username and password of mysql

Make sure the following library are installed.

    flask, flask_sqlalchemy, flask_login, mysql-connector-python



_________________________

GET endpoints
_________________________

/users

/users/<user_id>

/books

/books/<book_id>

/borrowed-books/<user_id>


___________________________

POST endpoints
___________________________

/users

INPUT: form-data
{ 
    "username": "" , 
    "password": "",
    "email":""
}


/books

INPUT: form-data
{
    "title":"", 
    "isbn":"", 
    "published_date":"",
    "genre":""
}


/books/<book_id>/details

INPUT: JSON
{
    "NumberOfPages":"", 
    "Publisher":"", 
    "Language":""
}

/borrow


INPUT: JSON
{
    "BookID":"",
    "ReturnDate":""
}


______________________________

PUT
_______________________________

/books/<book_id>/details

Input: JSON
{
    "NumberOfPages":"", 
    "Publisher":"", 
    "Language":""
}

/return/<book_id>


