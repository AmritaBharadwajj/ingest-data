# data_processing.py


from .models import GoogleDriveData

def process_google_drive_data(api_key):
    from .api_interaction import fetch_google_drive_data
    data = fetch_google_drive_data(api_key)
    
    # for item in data.get('items', []):
    #     google_drive_data = GoogleDriveData(...)  
    #     db.session.add(google_drive_data)
    # db.session.commit()
import json
from app import db 
from .models import Activity, ActivityEvent

def store_activities_from_json(json_data):
    data = json.loads(json_data)

    for item in data['items']:
        activity = Activity(
            time=item['id']['time'],
            unique_qualifier=item['id']['uniqueQualifier'],
            application_name=item['id']['applicationName'],
            customer_id=item['id']['customerId'],
            actor_email=item['actor']['email'],
            actor_profile_id=item['actor']['profileId'],
            ip_address=item['ipAddress']
        )

        for event in item['events']:
            activity.events.append(ActivityEvent(
                type=event['type'],
                name=event['name']
            ))

        db.session.add(activity)

    db.session.commit()


