from flask import Blueprint, request, jsonify
from app import db, app
from models import (
    FileHashCheck, IPCheck, URLCheck,
    FileHashEntry, IPEntry, URLEntry,
    ActivityLog
)
from datetime import datetime
import requests
import hashlib
import re
from urllib.parse import urlparse
import base64

# Blueprints
check_bp = Blueprint('check', __name__)
database_bp = Blueprint('database', __name__)
logs_bp = Blueprint('logs', __name__)

# Helper functions
def log_activity(action, details, status):
    log = ActivityLog(
        action=action,
        details=details,
        status=status
    )
    db.session.add(log)
    db.session.commit()

def check_virustotal(resource_type, resource):
    if not app.config['VIRUSTOTAL_API_KEY']:
        print("No VirusTotal API key configured")
        return None
    
    headers = {
        'x-apikey': app.config['VIRUSTOTAL_API_KEY']
    }
    
    if resource_type == 'file':
        url = f'https://www.virustotal.com/api/v3/files/{resource}'
    elif resource_type == 'ip':
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{resource}'
    else:  # url
        # For URLs, we need to use base64url encoding
        url_bytes = resource.encode('utf-8')
        encoded_url = base64.urlsafe_b64encode(url_bytes).decode('utf-8').rstrip('=')
        url = f'https://www.virustotal.com/api/v3/urls/{encoded_url}'
    
    print(f"Making VirusTotal API request to: {url}")
    
    try:
        response = requests.get(url, headers=headers)
        print(f"VirusTotal API response status: {response.status_code}")
        if response.status_code == 200:
            return response.json()
        else:
            print(f"VirusTotal API error response: {response.text}")
    except Exception as e:
        print(f"VirusTotal API error: {str(e)}")
    return None

def determine_hash_type(hash_value):
    if len(hash_value) == 32:
        return 'md5'
    elif len(hash_value) == 40:
        return 'sha1'
    elif len(hash_value) == 64:
        return 'sha256'
    return None

def parse_url(url):
    parsed = urlparse(url)
    return {
        'domain': parsed.netloc,
        'protocol': parsed.scheme,
        'path': parsed.path
    }

# Check routes
@check_bp.route('/file', methods=['GET'])
def check_file():
    file_hash = request.args.get('hash')
    use_virustotal = request.args.get('virustotal', 'false').lower() == 'true'
    
    if not file_hash:
        return jsonify({'error': 'No hash provided'}), 400
    
    # Validate hash format
    hash_pattern = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'  # MD5, SHA-1, or SHA-256
    if not re.match(hash_pattern, file_hash):
        return jsonify({
            'error': 'Invalid hash format. Please provide a valid MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars) hash.'
        }), 400
    
    # Check local database
    entry = FileHashEntry.query.filter_by(value=file_hash).first()
    status = 'clean'
    details = {}
    vt_data = None
    
    if entry:
        status = 'malicious' if entry.threat_level in ['high', 'critical'] else 'suspicious'
        details = {
            'threatLevel': entry.threat_level,
            'description': entry.description,
            'source': 'local_database'
        }
        # Only check VirusTotal if explicitly requested
        if use_virustotal:
            vt_data = check_virustotal('file', file_hash)
    else:
        # No local entry found, check VirusTotal
        vt_data = check_virustotal('file', file_hash)
        if vt_data and 'data' in vt_data and 'attributes' in vt_data['data']:
            vt_attributes = vt_data['data']['attributes']
            if 'last_analysis_stats' in vt_attributes:
                stats = vt_attributes['last_analysis_stats']
                if stats.get('malicious', 0) > 0:
                    status = 'malicious'
                    details = {
                        'threatLevel': 'high',
                        'description': f'Detected by {stats["malicious"]} antivirus engines',
                        'virustotal': True,
                        'source': 'virustotal'
                    }
                elif stats.get('suspicious', 0) > 0:
                    status = 'suspicious'
                    details = {
                        'threatLevel': 'medium',
                        'description': f'Marked as suspicious by {stats["suspicious"]} engines',
                        'virustotal': True,
                        'source': 'virustotal'
                    }
    
    # Save check result
    check = FileHashCheck(
        value=file_hash,
        status=status,
        details=details,
        virus_total_data=vt_data,
        hash_type=determine_hash_type(file_hash)
    )
    db.session.add(check)
    db.session.commit()
    
    log_activity('check_file', f'Checked file hash: {file_hash}', status)
    
    # Only include VirusTotal data in response if we have it and either:
    # 1. No local entry was found, or
    # 2. VirusTotal check was explicitly requested
    response_data = {
        'status': status,
        'details': details
    }
    
    if vt_data and (not entry or use_virustotal):
        response_data['virusTotal'] = vt_data
    
    return jsonify(response_data)

@check_bp.route('/ip', methods=['GET'])
def check_ip():
    ip_address = request.args.get('address', '').strip()
    use_virustotal = request.args.get('virustotal', 'false').lower() == 'true'
    
    if not ip_address:
        return jsonify({'error': 'No IP address provided'}), 400
    
    # Validate IP address format
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip_address):
        return jsonify({'error': 'Invalid IP address format. Please enter a valid IPv4 address (e.g., 192.168.1.1)'}), 400
    
    # Additional validation for IP octet values
    try:
        octets = ip_address.split('.')
        if not all(0 <= int(octet) <= 255 for octet in octets):
            return jsonify({'error': 'Invalid IP address: each octet must be between 0 and 255'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid IP address format'}), 400
    
    # Check local database
    entry = IPEntry.query.filter_by(value=ip_address).first()
    status = 'clean'
    details = {}
    
    if entry:
        status = 'malicious' if entry.threat_level in ['high', 'critical'] else 'suspicious'
        details = {
            'threatLevel': entry.threat_level,
            'description': entry.description,
            'source': 'local_database'
        }
    
    # Check VirusTotal if requested or if no local entry found
    vt_data = None
    if use_virustotal or not entry:
        vt_data = check_virustotal('ip', ip_address)
        if vt_data and 'data' in vt_data and 'attributes' in vt_data['data']:
            vt_attributes = vt_data['data']['attributes']
            if 'last_analysis_stats' in vt_attributes:
                stats = vt_attributes['last_analysis_stats']
                if stats.get('malicious', 0) > 0:
                    status = 'malicious'
                    details = {
                        'threatLevel': 'high',
                        'description': f'Detected by {stats["malicious"]} security vendors',
                        'virustotal': True,
                        'source': 'virustotal'
                    }
                elif stats.get('suspicious', 0) > 0:
                    status = 'suspicious'
                    details = {
                        'threatLevel': 'medium',
                        'description': f'Marked as suspicious by {stats["suspicious"]} vendors',
                        'virustotal': True,
                        'source': 'virustotal'
                    }
    
    # Save check result
    check = IPCheck(
        value=ip_address,
        status=status,
        details=details,
        virus_total_data=vt_data,
        ip_version='ipv4'
    )
    db.session.add(check)
    db.session.commit()
    
    log_activity('check_ip', f'Checked IP address: {ip_address}', status)
    
    response_data = {
        'status': status,
        'details': details
    }
    
    if vt_data and (not entry or use_virustotal):
        response_data['virusTotal'] = vt_data
    
    return jsonify(response_data)

@check_bp.route('/url', methods=['GET'])
def check_url():
    url = request.args.get('url', '').strip()
    use_virustotal = request.args.get('virustotal', 'false').lower() == 'true'
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Basic URL validation
    try:
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return jsonify({'error': 'Invalid URL format'}), 400
    except:
        return jsonify({'error': 'Invalid URL format'}), 400
    
    # Check local database
    entry = URLEntry.query.filter_by(value=url).first()
    status = 'clean'
    details = {}
    
    if entry:
        status = 'malicious' if entry.threat_level in ['high', 'critical'] else 'suspicious'
        details = {
            'threatLevel': entry.threat_level,
            'description': entry.description,
            'source': 'local_database'
        }
    
    # Check VirusTotal if requested or if no local entry found
    vt_data = None
    if use_virustotal or not entry:
        vt_data = check_virustotal('url', url)
        if vt_data and 'data' in vt_data and 'attributes' in vt_data['data']:
            vt_attributes = vt_data['data']['attributes']
            if 'last_analysis_stats' in vt_attributes:
                stats = vt_attributes['last_analysis_stats']
                if stats.get('malicious', 0) > 0:
                    status = 'malicious'
                    details = {
                        'threatLevel': 'high',
                        'description': f'Detected by {stats["malicious"]} security vendors',
                        'virustotal': True,
                        'source': 'virustotal'
                    }
                elif stats.get('suspicious', 0) > 0:
                    status = 'suspicious'
                    details = {
                        'threatLevel': 'medium',
                        'description': f'Marked as suspicious by {stats["suspicious"]} vendors',
                        'virustotal': True,
                        'source': 'virustotal'
                    }
    
    # Parse URL components
    url_info = parse_url(url)
    
    # Save check result
    check = URLCheck(
        value=url,
        status=status,
        details=details,
        virus_total_data=vt_data,
        domain=url_info['domain'],
        protocol=url_info['protocol']
    )
    db.session.add(check)
    db.session.commit()
    
    log_activity('check_url', f'Checked URL: {url}', status)
    
    response_data = {
        'status': status,
        'details': details
    }
    
    if vt_data and (not entry or use_virustotal):
        response_data['virusTotal'] = vt_data
    
    return jsonify(response_data)

@check_bp.route('/calculate-hash', methods=['POST'])
def calculate_hash():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Read file content
    content = file.read()
    
    # Calculate hashes
    md5_hash = hashlib.md5(content).hexdigest()
    sha1_hash = hashlib.sha1(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()
    
    return jsonify({
        'md5': md5_hash,
        'sha1': sha1_hash,
        'sha256': sha256_hash
    })

@database_bp.route('/stats', methods=['GET'])
def get_database_stats():
    stats = {
        'file_hashes': FileHashEntry.query.count(),
        'ip_addresses': IPEntry.query.count(),
        'urls': URLEntry.query.count(),
        'total_checks': {
            'file': FileHashCheck.query.count(),
            'ip': IPCheck.query.count(),
            'url': URLCheck.query.count()
        }
    }
    return jsonify(stats)

@database_bp.route('/entries', methods=['GET'])
def get_database_entries():
    entry_type = request.args.get('type', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    if entry_type == 'file':
        entries = FileHashEntry.query.paginate(page=page, per_page=per_page)
    elif entry_type == 'ip':
        entries = IPEntry.query.paginate(page=page, per_page=per_page)
    elif entry_type == 'url':
        entries = URLEntry.query.paginate(page=page, per_page=per_page)
    else:
        # Return all types
        file_entries = FileHashEntry.query.all()
        ip_entries = IPEntry.query.all()
        url_entries = URLEntry.query.all()
        
        entries = {
            'file_hashes': [{'id': e.id, 'value': e.value, 'threat_level': e.threat_level} for e in file_entries],
            'ip_addresses': [{'id': e.id, 'value': e.value, 'threat_level': e.threat_level} for e in ip_entries],
            'urls': [{'id': e.id, 'value': e.value, 'threat_level': e.threat_level} for e in url_entries]
        }
        return jsonify(entries)
    
    return jsonify({
        'items': [{'id': e.id, 'value': e.value, 'threat_level': e.threat_level} for e in entries.items],
        'total': entries.total,
        'pages': entries.pages,
        'current_page': entries.page
    })

@database_bp.route('/add', methods=['POST'])
def add_database_entry():
    data = request.get_json()
    
    if not data or 'type' not in data or 'value' not in data or 'threat_level' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    entry_type = data['type']
    value = data['value']
    threat_level = data['threat_level']
    description = data.get('description', '')
    
    # Validate threat level
    if threat_level not in ['low', 'medium', 'high', 'critical']:
        return jsonify({'error': 'Invalid threat level'}), 400
    
    try:
        if entry_type == 'file':
            # Validate hash format
            hash_pattern = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
            if not re.match(hash_pattern, value):
                return jsonify({'error': 'Invalid hash format'}), 400
            
            entry = FileHashEntry(
                value=value,
                threat_level=threat_level,
                description=description,
                hash_type=determine_hash_type(value)
            )
        elif entry_type == 'ip':
            # Validate IP format
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if not re.match(ip_pattern, value):
                return jsonify({'error': 'Invalid IP address format'}), 400
            
            # Validate IP octets
            octets = value.split('.')
            if not all(0 <= int(octet) <= 255 for octet in octets):
                return jsonify({'error': 'Invalid IP address: each octet must be between 0 and 255'}), 400
            
            entry = IPEntry(
                value=value,
                threat_level=threat_level,
                description=description,
                ip_version='ipv4'
            )
        elif entry_type == 'url':
            # Validate URL format
            try:
                parsed = urlparse(value)
                if not all([parsed.scheme, parsed.netloc]):
                    return jsonify({'error': 'Invalid URL format'}), 400
            except:
                return jsonify({'error': 'Invalid URL format'}), 400
            
            url_info = parse_url(value)
            entry = URLEntry(
                value=value,
                threat_level=threat_level,
                description=description,
                domain=url_info['domain'],
                protocol=url_info['protocol'],
                path=url_info['path']
            )
        else:
            return jsonify({'error': 'Invalid entry type'}), 400
        
        db.session.add(entry)
        db.session.commit()
        
        log_activity('add_entry', f'Added {entry_type} entry: {value}', 'success')
        
        return jsonify({
            'message': 'Entry added successfully',
            'id': entry.id
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@database_bp.route('/delete/<int:entry_id>', methods=['DELETE'])
def delete_database_entry(entry_id):
    entry_type = request.args.get('type')
    
    if not entry_type:
        return jsonify({'error': 'Entry type not specified'}), 400
    
    try:
        if entry_type == 'file':
            entry = FileHashEntry.query.get(entry_id)
        elif entry_type == 'ip':
            entry = IPEntry.query.get(entry_id)
        elif entry_type == 'url':
            entry = URLEntry.query.get(entry_id)
        else:
            return jsonify({'error': 'Invalid entry type'}), 400
        
        if not entry:
            return jsonify({'error': 'Entry not found'}), 404
        
        value = entry.value
        db.session.delete(entry)
        db.session.commit()
        
        log_activity('delete_entry', f'Deleted {entry_type} entry: {value}', 'success')
        
        return jsonify({'message': 'Entry deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@database_bp.route('/search', methods=['GET'])
def search_database():
    query = request.args.get('q', '')
    entry_type = request.args.get('type', 'all')
    
    if not query:
        return jsonify({'error': 'No search query provided'}), 400
    
    try:
        if entry_type == 'file':
            entries = FileHashEntry.query.filter(FileHashEntry.value.ilike(f'%{query}%')).all()
            results = [{'id': e.id, 'value': e.value, 'threat_level': e.threat_level} for e in entries]
        elif entry_type == 'ip':
            entries = IPEntry.query.filter(IPEntry.value.ilike(f'%{query}%')).all()
            results = [{'id': e.id, 'value': e.value, 'threat_level': e.threat_level} for e in entries]
        elif entry_type == 'url':
            entries = URLEntry.query.filter(URLEntry.value.ilike(f'%{query}%')).all()
            results = [{'id': e.id, 'value': e.value, 'threat_level': e.threat_level} for e in entries]
        else:
            # Search all types
            file_entries = FileHashEntry.query.filter(FileHashEntry.value.ilike(f'%{query}%')).all()
            ip_entries = IPEntry.query.filter(IPEntry.value.ilike(f'%{query}%')).all()
            url_entries = URLEntry.query.filter(URLEntry.value.ilike(f'%{query}%')).all()
            
            results = {
                'file_hashes': [{'id': e.id, 'value': e.value, 'threat_level': e.threat_level} for e in file_entries],
                'ip_addresses': [{'id': e.id, 'value': e.value, 'threat_level': e.threat_level} for e in ip_entries],
                'urls': [{'id': e.id, 'value': e.value, 'threat_level': e.threat_level} for e in url_entries]
            }
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@logs_bp.route('', methods=['GET'])
def get_logs():
    # Get filter parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    action = request.args.get('action')
    status = request.args.get('status')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    # Build query
    query = ActivityLog.query
    
    if start_date:
        query = query.filter(ActivityLog.created_at >= datetime.fromisoformat(start_date))
    if end_date:
        query = query.filter(ActivityLog.created_at <= datetime.fromisoformat(end_date))
    if action:
        query = query.filter(ActivityLog.action == action)
    if status:
        query = query.filter(ActivityLog.status == status)
    
    # Order by most recent first
    query = query.order_by(ActivityLog.created_at.desc())
    
    # Paginate results
    logs = query.paginate(page=page, per_page=per_page)
    
    return jsonify({
        'items': [{
            'id': log.id,
            'action': log.action,
            'details': log.details,
            'status': log.status,
            'created_at': log.created_at.isoformat()
        } for log in logs.items],
        'total': logs.total,
        'pages': logs.pages,
        'current_page': logs.page
    })

@logs_bp.route('/export', methods=['GET'])
def export_logs():
    # Get filter parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    action = request.args.get('action')
    status = request.args.get('status')
    
    # Build query
    query = ActivityLog.query
    
    if start_date:
        query = query.filter(ActivityLog.created_at >= datetime.fromisoformat(start_date))
    if end_date:
        query = query.filter(ActivityLog.created_at <= datetime.fromisoformat(end_date))
    if action:
        query = query.filter(ActivityLog.action == action)
    if status:
        query = query.filter(ActivityLog.status == status)
    
    # Order by most recent first
    logs = query.order_by(ActivityLog.created_at.desc()).all()
    
    # Format logs for export
    export_data = [{
        'id': log.id,
        'action': log.action,
        'details': log.details,
        'status': log.status,
        'created_at': log.created_at.isoformat()
    } for log in logs]
    
    return jsonify(export_data) 