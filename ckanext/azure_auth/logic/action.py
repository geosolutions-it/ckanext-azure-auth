from ckan.logic.action.create import user_create as core_user_create
import ckanext.azure_auth.logic.schema as azure_user_schema


def azure_user_create(context, data_dict):
    # Inject our custom schema into the context
    if 'schema' not in context:
        context['schema'] = azure_user_schema.custom_user_schema()
    
    # Call the CORE function directly to avoid recursion
    return core_user_create(context, data_dict)