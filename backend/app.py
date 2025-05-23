from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import requests
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:myPassword@localhost/threat_intel')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['VIRUSTOTAL_API_KEY'] = os.getenv('VIRUSTOTAL_API_KEY', '')

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Import models and routes after db initialization
from models import (
    FileHashCheck, IPCheck, URLCheck,
    FileHashEntry, IPEntry, URLEntry,
    ActivityLog
)
from routes import check_bp, database_bp, logs_bp

# Register blueprints
app.register_blueprint(check_bp, url_prefix='/api/check')
app.register_blueprint(database_bp, url_prefix='/api/database')
app.register_blueprint(logs_bp, url_prefix='/api/logs')

# Serve frontend file
@app.route('/')
def serve_frontend():
    return send_file('../frontend', mimetype='text/html')

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True) 