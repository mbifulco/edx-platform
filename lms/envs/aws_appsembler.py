# aws_appsembler.py

from .aws import *
from .appsembler import *


#comment these out for migration
INSTALLED_APPS += ('appsembler','aquent_data_migration',)
#INSTALLED_APPS += ('appsembler','aquent_data_migration','accredible_certificate',)

#TEMPLATE_CONTEXT_PROCESSORS += ('appsembler.context_processors.intercom',)