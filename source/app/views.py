from app import app
from flask import render_template, flash, request, redirect, session
from packetenizer import parse_and_analyze
from random import randint
from .helper import serialized_dict_storage, manage_file_parse

@app.route('/')
def index():
    session_present = False
    # Necessary because cookies will stay in browser even if server is restarted, but the dictionary will be empty
    if 'id' in session and session['id'] in serialized_dict_storage: 
        session_present = True 
    return render_template('index.html', session_present=session_present)

@app.route('/file', methods=['POST'])
def file_upload():
    if 'dump-file' not in request.files:
        # File not uploaded
        flash("No file uploaded!")
        return redirect('/')
    dump_file = request.files['dump-file']
    if dump_file.filename == '':
        # Again empty file
        flash("Empty file!")
        return redirect('/')
    return_value, status = manage_file_parse(dump_file)
    if status == False:
        flash(return_value)
        return redirect('/')
    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
    if 'id' not in session or session['id'] not in serialized_dict_storage:
        flash("Session not set. Please upload file")
        return redirect('/')
    data = serialized_dict_storage[session['id']]
    return render_template('dashboard.html', data=data, session_id=session['id'])

@app.route('/share/<session_id>')
def share_session(session_id):
    if int(session_id) in serialized_dict_storage:
        session['id'] = int(session_id)
        return redirect('/dashboard')
    else:
        flash("Not a valid share url")
        return redirect('/')