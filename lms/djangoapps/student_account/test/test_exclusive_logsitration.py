# -*- coding: utf-8 -*-
""" Tests for student account views. """

import logging
import re
from unittest import skipUnless
from urllib import urlencode

import mock
import ddt
from django.conf import settings
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.urlresolvers import reverse
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.messages.middleware import MessageMiddleware
from django.test import TestCase
from django.test.utils import override_settings
from django.http import HttpRequest
from edx_oauth2_provider.tests.factories import ClientFactory, AccessTokenFactory, RefreshTokenFactory
from edx_rest_api_client import exceptions
from nose.plugins.attrib import attr
from oauth2_provider.models import (
    AccessToken as dot_access_token,
    RefreshToken as dot_refresh_token
)
from provider.oauth2.models import (
    AccessToken as dop_access_token,
    RefreshToken as dop_refresh_token
)
from testfixtures import LogCapture

from commerce.models import CommerceConfiguration
from commerce.tests import TEST_API_URL, TEST_API_SIGNING_KEY, factories
from commerce.tests.mocks import mock_get_orders
from course_modes.models import CourseMode
from openedx.core.djangoapps.oauth_dispatch.tests import factories as dot_factories
from openedx.core.djangoapps.programs.tests.mixins import ProgramsApiConfigMixin
from openedx.core.djangoapps.user_api.accounts.api import activate_account, create_account
from openedx.core.djangoapps.user_api.accounts import EMAIL_MAX_LENGTH
from openedx.core.djangolib.js_utils import dump_js_escaped_json
from openedx.core.djangolib.testing.utils import CacheIsolationTestCase
from student.tests.factories import UserFactory
from student_account.views import account_settings_context, get_user_orders
from third_party_auth.tests.testutil import simulate_running_pipeline, ThirdPartyAuthTestMixin
from util.testing import UrlResetMixin
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from openedx.core.djangoapps.theming.tests.test_util import with_comprehensive_theme_context


LOGGER_NAME = 'audit'
User = get_user_model()  # pylint:disable=invalid-name


@attr(shard=3)
@ddt.ddt
@override_settings(
    # Sane Appsembler default settings
    APPSEMBLER_FEATURES={},
    CUSTOM_SSO_FIELDS_SYNC={},
    CUSTOM_LOGOUT_REDIRECT_URL='https://sso.auth/logout',
    EXCLUSIVE_SSO_LOGISTRATION_URL_MAP={},
)
class StudentAccountLoginAndRegistrationTest(ThirdPartyAuthTestMixin, UrlResetMixin, ModuleStoreTestCase):
    """ Tests for the student account views that update the user's account information. """

    USERNAME = "bob"
    EMAIL = "bob@example.com"
    PASSWORD = "password"

    URLCONF_MODULES = ['openedx.core.djangoapps.embargo']

    @mock.patch.dict(settings.FEATURES, {'EMBARGO': True})
    def setUp(self):
        super(StudentAccountLoginAndRegistrationTest, self).setUp()

        # For these tests, one third party auth provider is enabled
        self.configure_google_provider(enabled=True, visible=True)

    def test_partial_logistraion_url_map(self):
        self.fail('TODO: Support missing registration/login URL from `EXCLUSIVE_SSO_LOGISTRATION_URL_MAP`')

    @ddt.data(
        ("signin_user", "login", "https://sso.auth/login",),
        ("register_user", "register", "https://sso.auth/register"),
    )
    @ddt.unpack
    def test_exclusive_logistration(self, url_name, view_type, exclusive_sso_url):
        params = [
            ('course_id', 'course-v1:Org+Course+Run'),
            ('enrollment_action', 'enroll'),
            ('course_mode', CourseMode.DEFAULT_MODE_SLUG),
            ('email_opt_in', 'true'),
            ('next', '/custom/final/destination'),
        ]

        sso_settings = {
            'APPSEMBLER_FEATURES': {
                'ENABLE_EXCLUSIVE_SSO_LOGISTRATION': True,
            },
            'EXCLUSIVE_SSO_LOGISTRATION_URL_MAP': {
                view_type: exclusive_sso_url,
            },
        }

        # A sanity check
        self.assertRedirects(
            response=self.client.get(reverse('dashboard')),
            expected_url='{signin}?next=/dashboard'.format(signin=reverse('signin_user')),
            msg_prefix='The user should NOT be logged in',
            fetch_redirect_response=False,
        )

        self.assertContains(
            response=self.client.get(reverse(url_name), params),
            text='form',
            status_code=200,
            msg_prefix='Should NOT redirect: no running auth pipeline and feature is disabled.',
        )

        with override_settings(**sso_settings):
            self.assertRedirects(
                response=self.client.get(reverse(url_name), params),
                expected_url=exclusive_sso_url,
                msg_prefix='Should redirect: pipeline is NOT running AND the feature is enabled.',
                fetch_redirect_response=False,
            )

        pipeline_target = "student_account.views.third_party_auth.pipeline"
        with simulate_running_pipeline(pipeline_target, "google-oauth2"):
            self.assertContains(
                response=self.client.get(reverse(url_name), params),
                text='form',
                status_code=200,
                msg_prefix='Should NOT redirect: pipeline is running anyway AND the feature is disabled',
            )

        with override_settings(**sso_settings):
            with simulate_running_pipeline(pipeline_target, "google-oauth2"):
                self.assertContains(
                    response=self.client.get(reverse(url_name), params),
                    text='form',
                    status_code=200,
                    # Giving a chance for the `autoSubmitRegForm` to work, a redirect would prevent it.
                    msg_prefix='Should NOT redirect: Pipeline is running, regardless of the feature',
                )
