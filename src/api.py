from flask import Flask, request
from sofahutils import SofahLogger
import os
from honeypot.honeypot import Honeypot
app = Flask(__name__)


logger = SofahLogger(url=os.getenv('LOG_API', ''), dst_port=os.getenv('EXR_PORT', 0))
honeypot = Honeypot(logger=logger, answerset_path="/home/api/answerset/answerset.json")

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'CONNECT', 'TRACE'])
def catch_all(path):
    request.get_data()
    content = request.data.decode('utf-8')
    
    resp = honeypot.endpoint(path=path, args=request.args, content=content, http_method=request.method, ip=request.remote_addr, port=request.environ.get('REMOTE_PORT'))
    
    return resp
