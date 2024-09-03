import os
from flask import (
    Flask, flash, render_template,
    redirect, request, session, url_for)
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
if os.path.exists("env.py"):
    import env


app = Flask(__name__)

app.config["MONGO_DBNAME"] = os.environ.get("MONGO_DBNAME")
app.config["MONGO_URI"] = os.environ.get("MONGO_URI")
app.secret_key = os.environ.get("SECRET_KEY")

mongo = PyMongo(app)


@app.route("/")
@app.route("/get_tasks")
def get_tasks():
    tasks = mongo.db.tasks.find()
    return render_template("tasks.html", tasks=tasks)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        #Checks if the username already exists in the database
        #Use find_one() method on the Users collection in MongoDB
        #Checks if the MongoDB username field matches that of the input field of "username" in the form
        #Uses lower() method to compare as the user information is being stored in lowercase
        existing_user = mongo.db.users.find_one(
            {"username": request.form.get("username").lower()})
        
        #If there is a match in the database after user inputs username
        #Display message on screen using flash() method from Flask
        #Then redirect user back to the url_for() for the same register function so they can input another username
        if existing_user:
            flash("Username already exists")
            return redirect(url_for("register"))
        
        #Acts as 'else' statement if no existing user is found
        #Register variable is dictionary to be inserted into database
        #Remember to separate items in a dictionary with a comma ,
        register = {
            #Gets the username value from the form and stores in lowercase
            "username": request.form.get("username").lower(),
            #Uses werkzeug.security classes to hash the password got from the form
            "password": generate_password_hash(request.form.get("password"))
        }
        #Call the collection on MongoDB and uses inset_one() method to insert "register"
        mongo.db.users.insert_one(register)
        
        #Uses flask session function. Creates temporary session, like a page cookie
        #Targets the username field in the form element
        session["user"] = request.form.get("username").lower()
        #After username is placed into session, flash() message to user
        flash("Registration successful")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        #Check if username exists in database
        existing_user = mongo.db.users.find_one(
            {"username": request.form.get("username").lower()})

        if existing_user:
            #Ensures the hashed password matches user's inputted password
            #check_password_hash takes two arguments
            #The first is the key field (password in this case) wrapped in [ ] as it's part of existing_user variable
            #The second is the password the user supplied on the login form, requested the form element with the name of "password"
            if check_password_hash(existing_user["password"], request.form.get("password")):
                #Creates cookie for user which is set the the provided username in lowercase
                session["user"] = request.form.get("username").lower()
                #Displays welcome message. {} is a placeholder. format is the requested form element for "username"
                flash("Welcome, {}".format(request.form.get("username")))
            
            else:
                #Invalid password match, displays vague message to dissuade brute forcing
                flash("Incorrect Username and/or Password")
                return redirect(url_for("login"))
            
        else:
            #username doesn't exist
            flash("Incorrect Username and/or Password")
            return redirect(url_for("login"))

    return render_template("login.html")


if __name__ == "__main__":
    app.run(host=os.environ.get("IP"),
            port=int(os.environ.get("PORT")),
            debug=True)
