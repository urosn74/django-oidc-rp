import logging
import threading

from importlib import import_module
from django.conf import settings

from . import settings as static_oidc_rp_settings


_LOG = logging.getLogger(__name__)
_OIDC_RP_DYNAMIC_SETTINGS_BUILDER = getattr(
    settings, 'OIDC_RP_DYNAMIC_SETTINGS_BUILDER',
    None
)
_dynamic_settings_builder_resolved = False
_build_dynamic_settings = None
_THREAD_LOCALS = threading.local()


def _resolve_member(ref):
    ref_parts = ref.split('.')
    ref_module = '.'.join(ref_parts[:-1])
    ref_member = ref_parts[-1]
    mc_mod = import_module(ref_module)
    return getattr(mc_mod, ref_member, None)


def _get_oidc_rp_settings_builder():
    if _OIDC_RP_DYNAMIC_SETTINGS_BUILDER is not None:
        try:
            return _resolve_member(_OIDC_RP_DYNAMIC_SETTINGS_BUILDER)
        except:
            _LOG.error('failed to resolve builder function for dynamic OIDC RP settings', exc_info=True)
    return None


def build_oidc_rp_settings(request):
    builder = _get_oidc_rp_settings_builder()
    if builder:
        _LOG.debug('attempting to build dynamic OIDC RP settings')
        _THREAD_LOCALS.oidc_rp_settings = builder(request)


def release_oidc_rp_settings():
    _THREAD_LOCALS.oidc_rp_settings = None


def get_oidc_rp_settings():
    s = getattr(_THREAD_LOCALS, 'oidc_rp_settings', None)
    _LOG.debug('dynamic OIDC RP settings resolved to %s', s)
    return s if s else static_oidc_rp_settings
