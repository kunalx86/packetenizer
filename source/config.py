import os

class Config(object):
    DEBUG = True
    THREADS_PER_PAGE = 2

    if os.environ.get('SECRET_KEY'):
        SECRET_KEY = os.environ.get('SECRET_KEY')
    else:
        SECRET_KEY = 'sdansdajsd2@1s1nkn;Sad;0@121('

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_PERMANENT = True
    ENVIRONMENT = 'development'