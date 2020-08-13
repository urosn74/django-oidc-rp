from urllib.parse import urljoin, urlparse


class DynamicOidcSettings:

    def __init__(self,
                 provider_endpoint,
                 authorization_endpoint='authorize',
                 token_endpoint='token',
                 jwks_endpoint='jwks',
                 userinfo_endpoint='userinfo',
                 end_session_endpoint='logout',
                 end_session_redirect_uri_parameter='post_logout_redirect_uri',
                 end_session_id_token_parameter='id_token_hint',
                 client_id=None,
                 client_secret=None,
                 authentication_redirect_uri='/',
                 authentication_failure_redirect_uri='/',
                 user_details_handler=None,
                 unauthenticated_session_management_key=None,
                 realm=None):
        _parsed_provider_endpoint = urlparse(provider_endpoint)
        self.PROVIDER_ENDPOINT = provider_endpoint
        self.PROVIDER_URL = '{}://{}'.format(_parsed_provider_endpoint.scheme, _parsed_provider_endpoint.netloc)
        self.PROVIDER_AUTHORIZATION_ENDPOINT = urljoin(provider_endpoint, authorization_endpoint)
        self.PROVIDER_TOKEN_ENDPOINT = urljoin(provider_endpoint, token_endpoint)
        self.PROVIDER_JWKS_ENDPOINT = urljoin(provider_endpoint, jwks_endpoint)
        self.PROVIDER_USERINFO_ENDPOINT = urljoin(provider_endpoint, userinfo_endpoint)
        self.PROVIDER_END_SESSION_ENDPOINT = urljoin(provider_endpoint, end_session_endpoint)
        self.PROVIDER_END_SESSION_REDIRECT_URI_PARAMETER = end_session_redirect_uri_parameter
        self.PROVIDER_END_SESSION_ID_TOKEN_PARAMETER = end_session_id_token_parameter
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
        self._realm = realm

    @property
    def realm(self):
        return self._realm if realm else 'unknown'

    @property
    def provider_root(self):
        return urljoin(self.PROVIDER_URL, 'auth')
