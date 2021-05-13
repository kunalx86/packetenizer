from packetenizer import parse_and_analyze
from random import randint
from flask import session
from app import mongo
from bson.json_util import dumps
from bson.objectid import ObjectId

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
    # random_id = randint(100000, 1000000)
    # while random_id in serialized_dict_storage:
        # random_id = randint(100000, 1000000)
    inserted_doc = mongo.db.analyzed_info.insert({
        'tcp': return_value['tcp'],
        'udp': return_value['udp'],
        'dns': return_value['dns'],
        'icmp': return_value['icmp'],
        'invalid': return_value['invalid'],
        'analyze': return_value['analyze'],
        'file_name': dump_file.filename
    })
    session.permanent = True
    session['id'] = str(inserted_doc) 
    session['file_name'] = dump_file.filename
    return '', True

def test_session():
    id_sets = [str(_id) for _id in mongo.db.analyzed_info.find().distinct('_id')]
    if 'id' in session and session['id'] in id_sets:
        return '', True
    return "Session not set. Please upload file", False

def query_document(**kwargs):
    return mongo.db.analyzed_info.find_one({
        "_id": ObjectId(session['id'])
    }, kwargs)