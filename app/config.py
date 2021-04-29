import os
class Config:
    THREADS_PER_PAGE = 2
    SECRET_KEY = os.environ.get('SECRET_KEY') 
