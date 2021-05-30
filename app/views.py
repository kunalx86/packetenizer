from app import app
from flask import render_template, flash, request, redirect, session
from packetenizer import parse_and_analyze
from random import randint
from .helper import serialized_dict_storage, manage_file_parse, test_session

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
    return redirect('/dashboard/home')

@app.route('/dashboard')
def dashboard():
    return redirect('/dashboard/home')

@app.route('/dashboard/home')
def dashboard_home():
    return_value, status = test_session()
    if not status:
        flash(return_value)
        return redirect('/')
    data = serialized_dict_storage[session['id']]['analyze']['counts']
    return render_template('dashboard/home.html', data=data, nav_item="1",session_id=session['id'], file_name=session['file_name'])

@app.route('/dashboard/tcp')
def dashboard_tcp():
    return_value, status = test_session()
    if not status:
        flash(return_value)
        return redirect('/')
    data = serialized_dict_storage[session['id']]['tcp']
    return render_template('dashboard/tcp_details.html', nav_item="3",data=data, session_id=session['id'], file_name=session['file_name'])

@app.route('/dashboard/udp')
def dashboard_udp():
    return_value, status = test_session()
    if not status:
        flash(return_value)
        return redirect('/')
    data = serialized_dict_storage[session['id']]['udp']
    return render_template('dashboard/udp_details.html', nav_item="4",data=data, session_id=session['id'], file_name=session['file_name'])

@app.route('/dashboard/dns')
def dashboard_dns():
    return_value, status = test_session()
    if not status:
        flash(return_value)
        return redirect('/')
    data = serialized_dict_storage[session['id']]['dns']
    return render_template('dashboard/dns_details.html', nav_item="6",data=data, session_id=session['id'], file_name=session['file_name'])

@app.route('/dashboard/icmp')
def dashboard_icmp():
    return_value, status = test_session()
    if not status:
        flash(return_value)
        return redirect('/')
    data = serialized_dict_storage[session['id']]['icmp']
    return render_template('dashboard/icmp_details.html', nav_item="5",data=data, session_id=session['id'], file_name=session['file_name'])

@app.route('/dashboard/analysis')
def dashboard_analysis():
    return_value, status = test_session()
    if not status:
        flash(return_value)
        return redirect('/')
    data = serialized_dict_storage[session['id']]['analyze']
    return render_template('dashboard/analysis.html', nav_item="2",data=data, session_id=session['id'], file_name=session['file_name'])

@app.route('/dashboard/table')
def dashboard_table():
    return_value, status = test_session()
    if not status:
        flash(return_value)
        return redirect('/')
    data = {}
    data['tcp'] = serialized_dict_storage[session['id']]['analyze']['tcp']
    data['udp'] = serialized_dict_storage[session['id']]['analyze']['udp']
    return render_template('dashboard/table.html', nav_item="7",data=data, session_id=session['id'], file_name=session['file_name'])

@app.route('/share/<session_id>')
def share_session(session_id):
    if int(session_id) in serialized_dict_storage:
        session.permanent = False
        session['id'] = int(session_id)
        session['file_name'] = serialized_dict_storage[int(session_id)]['file_name'] 
        return redirect('/dashboard/home')
    else:
        flash("Not a valid share url")
        return redirect('/')

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html')