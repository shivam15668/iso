# ips.txt contains ip ranges
# masscan contains extracted ip
# server folder will contain  mongodb
# install mongodb community 
# sudo systemctl start mongod
# sudo systemctl stop mongod
# sudo systemctl restart mongod
# sudo systemctl enable mongod
# sudo systemctl status mongod
# sudo systemctl daemon-reload 
# mongosh
# sudo systemctl enable mongod.service # auto restart
# mongodb compass download for gui 
# pip install Flask
# pip install pymongo
# pip install gunicorn
# json module
# re module 
from flask import Flask, request, jsonify, Response , render_template_string
import json
from bson.regex import Regex
import re
from pymongo import MongoClient

app = Flask(__name__)
mongo_url = "mongodb://localhost:27017/"
client = MongoClient(mongo_url)
try:
    db = client["scannerdb"]
    collection = db["sslchecker"] # collections are in mongodb where we store all our information in json file 
    print(f"MongoDB connection successful")
except Exception as e:
    print(f"Error connection to MongoDB: {str(e)}")
    
@app.errorhandler(Exception)
def handle_database_error(e):
    return "An error occurred while connecting to database. ",500

# we will create a root now using decorator 
@app.route("/insert",methods = ["POST"])
def insert():
    try:
        result_json = request.get_json()
        collection.insert_many(result_json)
        # get json data from flask as requested by client add to container
        return jsonify({"message":"Inserted"}) # message is key , inserted value # res.text from scanner.py 
    except Exception as e: 
        print(f"Error while inserting data into the database: {str()}")
        return jsonify({"error":str(e)}),500
   
if __name__ == "__main__":
    app.run(host = "0.0.0.0", port = 5000 , debug = True) # app is Flask instance , run is method which runs   
    
    