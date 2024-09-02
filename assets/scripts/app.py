import os
from flask import Flask
if os.path.exists("env.py"):
    import env


app = Flask(__name__) #Create instance of Flask and store in variable: "app"


@app.route("/")
def hello():
    return "Hello World ... again"


if __name__ == "__main__":
    app.run(
        host=os.environ.get("IP"),
        port=int(os.environ.get("PORT", "5000")),
        debug=True
    )
 