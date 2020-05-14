"""
    OpenID Connect relying party (RP) utilities
    ===========================================

    This modules defines utilities allowing to manipulate ID tokens and other common helpers.

"""

import base64
import datetime as dt
import hashlib
import logging

from calendar import timegm
from urllib.parse import urlparse

from django.core.exceptions import SuspiciousOperation
from django.utils.encoding import force_bytes, smart_bytes
from jwkest import JWKESTException
from jwkest.jwk import KEYS
from jwkest.jws import JWS

from .conf import get_oidc_rp_settings


OIDC_SETUP_ATTRS = [
    'PROVIDER_ENDPOINT', 'PROVIDER_URL', 'PROVIDER_AUTHORIZATION_ENDPOINT',
    'PROVIDER_TOKEN_ENDPOINT', 'PROVIDER_JWKS_ENDPOINT', 'PROVIDER_USERINFO_ENDPOINT',
    'PROVIDER_USERINFO_ENDPOINT', 'PROVIDER_END_SESSION_ENDPOINT',
    'PROVIDER_END_SESSION_REDIRECT_URI_PARAMETER', 'PROVIDER_END_SESSION_ID_TOKEN_PARAMETER',
    'PROVIDER_SIGNATURE_ALG', 'PROVIDER_SIGNATURE_KEY', 'CLIENT_ID',
    'CLIENT_SECRET', 'STATE_LENGTH', 'SCOPES', 'USE_NONCE', 'NONCE_LENGTH',
    'ID_TOKEN_MAX_AGE', 'ID_TOKEN_INCLUDE_USERINFO', 'AUTHENTICATION_REDIRECT_URI',
    'AUTHENTICATION_FAILURE_REDIRECT_URI', 'USER_DETAILS_HANDLER',
    'UNAUTHENTICATED_SESSION_MANAGEMENT_KEY'
]

_LOG = logging.getLogger(__name__)


class OidcSetup:
    pass


def get_active_oidc_setup(oidc_settings=None):
    return oidc_settings if oidc_settings else get_oidc_rp_settings()


def build_custom_oidc_setup(**kwargs):
    oidc_setup = OidcSetup()
    for key in OIDC_SETUP_ATTRS:
        setattr(
            oidc_setup,
            key,
            kwargs.get(key, getattr(get_oidc_rp_settings(), key, None))
        )
    return oidc_setup


def calculate_username_from_oidc_sub(sub):
    return base64.urlsafe_b64encode(hashlib.sha1(force_bytes(sub)).digest()).rstrip(b'=')


def validate_and_return_id_token(jws, nonce=None, validate_nonce=True, oidc_settings=None):
    """ Validates the id_token according to the OpenID Connect specification. """
    oidc_settings = get_active_oidc_setup(oidc_settings)
    shared_key = oidc_settings.CLIENT_SECRET \
        if oidc_settings.PROVIDER_SIGNATURE_ALG == 'HS256' \
        else oidc_settings.PROVIDER_SIGNATURE_KEY  # RS256

    try:
        # Decodes the JSON Web Token and raise an error if the signature is invalid.
        id_token = JWS().verify_compact(force_bytes(jws), _get_jwks_keys(shared_key, oidc_settings=oidc_settings))
    except JWKESTException:
        return

    # Validates the claims embedded in the id_token.
    _validate_claims(id_token, nonce=nonce, validate_nonce=validate_nonce, oidc_settings=oidc_settings)

    return id_token


def _get_jwks_keys(shared_key, oidc_settings=None):
    """ Returns JWKS keys used to decrypt id_token values. """
    # The OpenID Connect Provider (OP) uses RSA keys to sign/enrypt ID tokens and generate public
    # keys allowing to decrypt them. These public keys are exposed through the 'jwks_uri' and should
    # be used to decrypt the JWS - JSON Web Signature.
    if oidc_settings is None:
        oidc_settings = get_oidc_rp_settings()
    jwks_keys = KEYS()
    jwks_url = oidc_settings.PROVIDER_JWKS_ENDPOINT
    _LOG.debug('loading JWKS keys from %s', jwks_url)
    jwks_keys.load_from_url(jwks_url)
    # Adds the shared key (which can correspond to the client_secret) as an oct key so it can be
    # used for HMAC signatures.
    jwks_keys.add({'key': smart_bytes(shared_key), 'kty': 'oct'})
    return jwks_keys


def _validate_claims(id_token, nonce=None, validate_nonce=True, oidc_settings=None):
    """ Validates the claims embedded in the JSON Web Token. """
    if oidc_settings is None:
        oidc_settings = get_oidc_rp_settings()
    iss_parsed_url = urlparse(id_token['iss'])
    provider_parsed_url = urlparse(oidc_settings.PROVIDER_ENDPOINT)
    if iss_parsed_url.netloc != provider_parsed_url.netloc:
        raise SuspiciousOperation('Invalid issuer')

    if isinstance(id_token['aud'], str):
        id_token['aud'] = [id_token['aud']]

    if oidc_settings.CLIENT_ID not in id_token['aud']:
        raise SuspiciousOperation('Invalid audience')

    if len(id_token['aud']) > 1 and 'azp' not in id_token:
        raise SuspiciousOperation('Incorrect id_token: azp')

    if 'azp' in id_token and id_token['azp'] != oidc_settings.CLIENT_ID:
        raise SuspiciousOperation('Incorrect id_token: azp')

    utc_timestamp = timegm(dt.datetime.utcnow().utctimetuple())
    if utc_timestamp > id_token['exp']:
        raise SuspiciousOperation('Signature has expired')

    if 'nbf' in id_token and utc_timestamp < id_token['nbf']:
        raise SuspiciousOperation('Incorrect id_token: nbf')

    # Verifies that the token was issued in the allowed timeframe.
    if utc_timestamp > id_token['iat'] + oidc_settings.ID_TOKEN_MAX_AGE:
        raise SuspiciousOperation('Incorrect id_token: iat')

    # Validate the nonce to ensure the request was not modified if applicable.
    id_token_nonce = id_token.get('nonce', None)
    if validate_nonce and oidc_settings.USE_NONCE and id_token_nonce != nonce:
        raise SuspiciousOperation('Incorrect id_token: nonce')
