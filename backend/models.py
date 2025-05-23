from app import db
from datetime import datetime

class BaseThreatCheck(db.Model):
    __abstract__ = True
    
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'clean', 'suspicious', or 'malicious'
    details = db.Column(db.JSON)
    virus_total_data = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FileHashCheck(BaseThreatCheck):
    __tablename__ = 'file_hash_checks'
    
    hash_type = db.Column(db.String(10), nullable=False)  # 'md5', 'sha1', or 'sha256'

class IPCheck(BaseThreatCheck):
    __tablename__ = 'ip_checks'
    
    ip_version = db.Column(db.String(4), nullable=False)  # 'ipv4' or 'ipv6'

class URLCheck(BaseThreatCheck):
    __tablename__ = 'url_checks'
    
    domain = db.Column(db.String(255))
    protocol = db.Column(db.String(10))  # 'http' or 'https'

class BaseDatabaseEntry(db.Model):
    __abstract__ = True
    
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(255), nullable=False, unique=True)
    threat_level = db.Column(db.String(20), nullable=False)  # 'low', 'medium', 'high', or 'critical'
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FileHashEntry(BaseDatabaseEntry):
    __tablename__ = 'file_hash_entries'
    
    hash_type = db.Column(db.String(10), nullable=False)  # 'md5', 'sha1', or 'sha256'
    file_name = db.Column(db.String(255))
    file_size = db.Column(db.Integer)  # Size in bytes

class IPEntry(BaseDatabaseEntry):
    __tablename__ = 'ip_entries'
    
    ip_version = db.Column(db.String(4), nullable=False)  # 'ipv4' or 'ipv6'
    country = db.Column(db.String(2))  # ISO country code
    asn = db.Column(db.String(50))  # Autonomous System Number

class URLEntry(BaseDatabaseEntry):
    __tablename__ = 'url_entries'
    
    domain = db.Column(db.String(255))
    protocol = db.Column(db.String(10))  # 'http' or 'https'
    path = db.Column(db.String(255))
    last_seen = db.Column(db.DateTime)

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    status = db.Column(db.String(20), nullable=False)  # 'success', 'clean', 'suspicious', 'malicious', or 'error'
    created_at = db.Column(db.DateTime, default=datetime.utcnow) 