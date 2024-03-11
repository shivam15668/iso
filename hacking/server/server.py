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
except Exception as e:
    print(f"Error connection to MongoDB: {str(e)}")