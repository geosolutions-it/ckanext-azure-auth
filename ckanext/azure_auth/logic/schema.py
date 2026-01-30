from ckan.plugins import toolkit
from ckan.logic.schema import default_user_schema

def custom_user_schema():
    # Define the core schema
    schema = default_user_schema()
    
    # Grab the required validators we need from the toolkit
    ignore_missing = toolkit.get_validator('ignore_missing')
    user_password_validator = toolkit.get_validator('user_password_validator')
    user_password_not_empty = toolkit.get_validator('user_password_not_empty')
    unicode_safe = toolkit.get_validator('unicode_safe')
    
    # Replace the password logic with your new order
    # By putting ignore_missing FIRST, the others are skipped if the key isn't there
    schema['password'] = [
        ignore_missing, 
        user_password_validator, 
        user_password_not_empty, 
        unicode_safe
    ]
    
    return schema