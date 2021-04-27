import os
import json

with open('../config.json', 'r') as f:
    config = json.load(f)

class Config:
    THREADS_PER_PAGE = 2
    SECRET_KEY = config['SECRET_KEY'] 
