# aws_appsembler.py

from .aws import *
from .appsembler import *

INSTALLED_APPS += ('appsembler',)
TEMPLATE_CONTEXT_PROCESSORS += ('appsembler.context_processors.intercom',)

SEARCH_SKIP_ENROLLMENT_START_DATE_FILTERING = True

#enable course visibility feature flags
COURSE_CATALOG_VISIBILITY_PERMISSION = 'see_in_catalog'
COURSE_ABOUT_VISIBILITY_PERMISSION = 'see_about_page'