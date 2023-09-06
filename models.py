from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()
from app import db 
class Activity(Base):
    __tablename__ = 'activities'

    id = Column(Integer, primary_key=True)
    time = Column(DateTime)
    unique_qualifier = Column(String)
    application_name = Column(String)
    customer_id = Column(String)
    actor_email = Column(String)
    actor_profile_id = Column(String)
    ip_address = Column(String)
    events = Column(JSON)
def __init__(self, time, unique_qualifier, application_name, customer_id, actor_email, actor_profile_id, ip_address, events):
        self.time = time
        self.unique_qualifier = unique_qualifier
        self.application_name = application_name
        self.customer_id = customer_id
        self.actor_email = actor_email
        self.actor_profile_id = actor_profile_id
        self.ip_address = ip_address
        self.events = events
        