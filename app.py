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
    #Converts the tasks to a Python list from a Mongo cursor object, allowing proper jinja iteration
    tasks = list(mongo.db.tasks.find())
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
        #Redirects user to the profile page, which is looking for variable "username" so set that to same session cookie of "user"
        return redirect(url_for("profile", username=session["user"]))
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
                return redirect(url_for("profile", username=session["user"]))
            
            else:
                #Invalid password match, displays vague message to dissuade brute forcing
                flash("Incorrect Username and/or Password")
                return redirect(url_for("login"))
            
        else:
            #username doesn't exist
            flash("Incorrect Username and/or Password")
            return redirect(url_for("login"))

    return render_template("login.html")

#Passing username variable in the app.route()
@app.route("/profile/<username>", methods=["GET", "POST"])
def profile(username):
    #Finds the username from the database using the session variable cookie and stores it in "username"
    #The [] at the end with "username" in specifies to only retrieve the username stored, not the password
    username = mongo.db.users.find_one({"username": session["user"]})["username"]
    
    #returns the appropriate profile of the user using the cookie if it's truthy.
    if session["user"]:
        #the first argument is what is expected to return
        #the second argument is the username variable defined above
        return render_template("profile.html", username=username)
    #if the cookie is false or doesn't exist, redirect to login
    return redirect(url_for("login"))

#Don't need to supply method, as GET is default and POST won't be used for this function
@app.route("/logout")
def logout():
    flash("You've been logged out")
    #Removes specified session cookie. Can use session.clear() to remove all applicable session cookies too
    session.pop("user")
    return redirect(url_for("login"))


@app.route("/add_task", methods=["GET", "POST"])
def add_task():
    #If the HTTP method being requested is POST
    if request.method == "POST":
        #Sets the is_urgent to on if the requested form element button is checked to on, otherwise it's off
        is_urgent = "on" if request.form.get("is_urgent") else "off"
        task = {
            "category_name": request.form.get("category_name"),
            "task_name": request.form.get("task_name"),
            "task_description": request.form.get("task_description"),
            "is_urgent": is_urgent,
            "due_date": request.form.get("due_date"),
            #created_by uses session cookie to get the username of the person adding the task and insert it into the dictionary
            "created_by": session["user"]
        }
        #Inserts the task variable dictionary above into the database
        mongo.db.tasks.insert_one(task)
        flash("Task Successfully Added")
        #Redirects user to get_tasks() function, which is the home page
        return redirect(url_for("get_tasks"))
    #If the method requested is GET, the default
    #Performs find() method on categories collection and sorts them alphabetically using '1' as the second argument in sort() method
    categories = mongo.db.categories.find().sort("category_name", 1)
    #Passes categories to the add_task template
    return render_template("add_task.html", categories=categories)


@app.route("/edit_task/<task_id>", methods=["GET", "POST"])
def edit_task(task_id):
    #If the HTTP method being requested is POST
    if request.method == "POST":
        #Sets the is_urgent to on if the requested form element button is checked to on, otherwise it's off
        is_urgent = "on" if request.form.get("is_urgent") else "off"
        submit = {
            "category_name": request.form.get("category_name"),
            "task_name": request.form.get("task_name"),
            "task_description": request.form.get("task_description"),
            "is_urgent": is_urgent,
            "due_date": request.form.get("due_date"),
            #created_by uses session cookie to get the username of the person adding the task and insert it into the dictionary
            "created_by": session["user"]
        }
        #Uses update_one(), takes two arguments which are both dictionaries.
        #First argument specifies the task being updated using the ObjectID from the database
        #Second is the dictionary from the submit variable above
        mongo.db.tasks.update_one({"_id": ObjectId(task_id)}, submit)
        flash("Task Successfully Updated")
    
    #Uses the database unique object id to retrieve the correct task
    #Need to import ObjectID from bson.objectid to be able to render MongoDB elements by unique ID
    task = mongo.db.tasks.find_one({"_id": ObjectId(task_id)})
    #Performs find() method on categories collection and sorts them alphabetically using '1' as the second argument in sort() method
    categories = mongo.db.categories.find().sort("category_name", 1)
    #Passes task variable from above and categories to the edit_task template and returns user to the same edit page
    return render_template("edit_task.html", task=task, categories=categories)


@app.route("/delete_task/<task_id>")
def delete_task(task_id):
    mongo.db.tasks.delete_one({"_id": ObjectId(task_id)})
    flash("Task Succesfully Deleted")
    return render_template(url_for("get_tasks"))


if __name__ == "__main__":
    app.run(host=os.environ.get("IP"),
            port=int(os.environ.get("PORT")),
            debug=True)
