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

## Run Flask App
- `flask run`