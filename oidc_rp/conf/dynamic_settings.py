import threading

from importlib import import_module
from urllib.parse import urljoin, urlparse
from django.conf import settings

from . import settings as static_oidc_rp_settings


_THREAD_LOCALS = threading.local()
_OIDC_RP_DYNAMIC_SETTINGS_BUILDER = getattr(
    settings, 'OIDC_RP_DYNAMIC_SETTINGS_BUILDER',
    None
)


def _resolve_member(ref):
    ref_parts = ref.split('.')
    ref_module = '.'.join(ref_parts[:-1])
    ref_member = ref_parts[-1]
    mc_mod = import_module(ref_module)
    return getattr(mc_mod, ref_member, None)


if _OIDC_RP_DYNAMIC_SETTINGS_BUILDER is not None:
    try:
        _build_dynamic_settings = _resolve_member(_OIDC_RP_DYNAMIC_SETTINGS_BUILDER)
    except:
        _build_dynamic_settings = None


def build_oidc_rp_settings(request):
    if _build_dynamic_settings:
        _THREAD_LOCALS.oidc_rp_settings = _build_dynamic_settings(request)


def release_oidc_rp_settings():
    _THREAD_LOCALS.oidc_rp_settings = None


def get_oidc_rp_settings():
    s = getattr(_THREAD_LOCALS, 'oidc_rp_settings', None)
    return s if s else static_oidc_rp_settings


class DynamicOidcSettings:

    def __init__(self,
                 provider_endpoint,
                 authorization_endpoint='authorize',
                 client_id=None,
                 client_secret=None,
                 authentication_redirect_uri='/',
                 authentication_failure_redirect_uri='/',
                 user_details_handler=None,
                 unauthenticated_session_management_key=None):
        _parsed_provider_endpoint = urlparse(provider_endpoint)
        self.PROVIDER_ENDPOINT = provider_endpoint
        self.PROVIDER_URL = '{}://{}'.format(_parsed_provider_endpoint.scheme, _parsed_provider_endpoint.netloc)
        self.PROVIDER_AUTHORIZATION_ENDPOINT = urljoin(provider_endpoint, authorization_endpoint)
        self.PROVIDER_TOKEN_ENDPOINT = urljoin(provider_endpoint, 'token')
        self.PROVIDER_JWKS_ENDPOINT = urljoin(provider_endpoint, 'jwks')
        self.PROVIDER_USERINFO_ENDPOINT = urljoin(provider_endpoint, 'userinfo')
        self.PROVIDER_END_SESSION_ENDPOINT = urljoin(provider_endpoint, 'logout')
        self.PROVIDER_END_SESSION_REDIRECT_URI_PARAMETER = 'post_logout_redirect_uri'
        self.PROVIDER_SIGNATURE_ALG = 'HS256'
        self.PROVIDER_SIGNATURE_KEY = None
        self.CLIENT_ID = client_id
        self.CLIENT_SECRET = client_secret
        self.STATE_LENGTH = 32
        self.SCOPES = 'openid email'
        self.USE_NONCE = True
        self.NONCE_LENGTH = 32
        self.ID_TOKEN_MAX_AGE = 600
        self.ID_TOKEN_INCLUDE_USERINFO = False
        self.AUTHENTICATION_REDIRECT_URI = authentication_redirect_uri
        self.AUTHENTICATION_FAILURE_REDIRECT_URI = authentication_failure_redirect_uri
        self.USER_DETAILS_HANDLER = user_details_handler
        self.UNAUTHENTICATED_SESSION_MANAGEMENT_KEY = unauthenticated_session_management_key
