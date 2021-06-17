<<<<<<< HEAD
# Python source file

## Python version 3.9.1

## Core Module (packetenizer)
- This is the core module although placement of files is bound to change
- Helper (helper) contains the other important classes

### Note: Commands to be run inside source directory unless stated otherwise

## Create virtualenv as follows (Run only once)
- `pip install virtualenv --user`
- `virtualenv -p /usr/bin/python3 env`

## Run everytime
- `source env/bin/activate`
- `pip install -r requirements.txt` (To stay up to date on modules)

## Run whenever a new package is installed
- `pip freeze > requirements.txt`

## Run python code for testing
- `python run_core.py samples/sample_file.pcap`

## Run everytime new shell session is started
- `export FLASK_APP=run.py`
- `export FLASK_ENV=development`
- For windows:
- `set FLASK_APP=run.py`
- `set FLASK_ENV=development`

## Run Flask App
- `flask run`
=======
# PACKETENIZER
![Packetenizer Logo](./source/app/static/images/Packetinizer_bg_3.jpg)
![Packetenizer](https://img.shields.io/badge/Packetenizer-1.0-green)
![Authors](https://img.shields.io/badge/Authors-Kunal%20Joshi,%20Jainam%20Joshi,%20Brijesh%20Ghonia-green)
[![License](https://img.shields.io/badge/License-GPLv2-green)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Website](https://img.shields.io/badge/Website-packetenizer.herokuapp.com-green)](https://packetenizer.herokuapp.com)
[![made-with-python](https://img.shields.io/badge/Made%20with-Python-green)](https://www.python.org/)

Packetenizer is a project developed by Kunal Joshi, Jainam Joshi and Brijesh Ghonia for our Diploma 3rd Year Project.
Various aspects of this project are covered in modules.md, project.md files.

## Setup
- You can use Docker to run the application
- For running directly refer `./source/README.md`
- Please create environment variables as referred in `.env.example` file
- If you are using Docker, remember to rename `.env.example` to `.env`
- In root of project simply run `docker-compose up --build`
- Once image is built, the application will be visible on `http://localhost:5000` 🥳
>>>>>>> main
