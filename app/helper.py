from packetenizer import parse_and_analyze
from random import randint
from flask import session

ALLOWED_EXTENSIONS = ['pcap', 'pcapng', 'cap']

serialized_dict_storage = {}

def allowed_file(filename: str):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def manage_file_parse(dump_file):
    if dump_file and not allowed_file(dump_file.filename):
        return "File extension not supported!", False
    return_value, status = parse_and_analyze(dump_file)
    if not status:
        return return_value, status
    random_id = randint(100000, 1000000)
    while random_id in serialized_dict_storage:
        random_id = randint(100000, 1000000)
    session.permanent = True
    session['id'] = random_id
    session['file_name'] = dump_file.filename
    serialized_dict_storage[random_id] = return_value
    serialized_dict_storage[random_id]['file_name'] = dump_file.filename
    return '', True

def test_session():
    if 'id' in session and session['id'] in serialized_dict_storage:
        return '', True
    return "Session not set. Please upload file", False