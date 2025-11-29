"""
Database models for GeoSense
MongoDB document models using MongoEngine
"""

from flask_mongoengine import MongoEngine
from datetime import datetime
from database.db import db

class TrafficData(db.Document):
    """Traffic data model"""
    location = db.PointField(required=True)
    timestamp = db.DateTimeField(default=datetime.utcnow)
    traffic_level = db.IntField(required=True)
    speed = db.FloatField()
    volume = db.IntField()
    
    meta = {
        'collection': 'traffic_data',
        'indexes': ['location', 'timestamp']
    }

class POI(db.Document):
    """Point of Interest model"""
    name = db.StringField(required=True)
    location = db.PointField(required=True)
    category = db.StringField(required=True)
    metadata = db.DictField()
    
    meta = {
        'collection': 'pois',
        'indexes': ['location', 'category']
    }

class Route(db.Document):
    """Route model"""
    origin = db.PointField(required=True)
    destination = db.PointField(required=True)
    route_type = db.StringField(choices=['fastest', 'cheapest', 'eco-friendly'])
    waypoints = db.ListField(db.PointField())
    distance = db.FloatField()
    duration = db.FloatField()
    cost = db.FloatField()
    carbon_emission = db.FloatField()
    created_at = db.DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'routes',
        'indexes': ['origin', 'destination', 'route_type']
    }

class Report(db.Document):
    """Report model"""
    report_type = db.StringField(required=True)
    stakeholder_type = db.StringField(choices=['government', 'researcher', 'engineer'])
    file_path = db.StringField(required=True)
    file_format = db.StringField(choices=['pdf', 'csv'])
    generated_at = db.DateTimeField(default=datetime.utcnow)
    parameters = db.DictField()
    
    meta = {
        'collection': 'reports',
        'indexes': ['report_type', 'stakeholder_type', 'generated_at']
    }

class User(db.Document):
    name = db.StringField(required=True, max_length=100)
    email = db.EmailField(required=True, unique=True)
    password = db.StringField(required=True)
    created_at = db.DateTimeField(default=datetime.utcnow)  # FIXED: removed datetime.datetime
    updated_at = db.DateTimeField(default=datetime.utcnow)  # FIXED: removed datetime.datetime
    
    def to_json(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'email': self.email,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    meta = {
        'collection': 'users',
        'indexes': ['email']
    }