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

{
    "NumberOfPages":"", 
    "Publisher":"", 
    "Language":""
}

/return/<book_id>


