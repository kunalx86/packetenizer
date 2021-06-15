# Copyright (C) 2021 Kunal Joshi, Jainam Joshi, Brijesh Ghonia

import os

class Config:
    THREADS_PER_PAGE = 2

    if os.environ.get('SECRET_KEY'):
        SECRET_KEY = os.environ.get('SECRET_KEY')
    else:
        SECRET_KEY = 'sdansdajsd2@1s1nkn;Sad;0@121('
