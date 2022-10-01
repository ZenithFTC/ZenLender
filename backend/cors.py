"""
    flask_cors
    ~~~~
    Flask-CORS is a simple extension to Flask allowing you to support cross
    origin resource sharing (CORS) using a simple decorator.

    :copyright: (c) 2016 by Cory Dolphin.
    :license: MIT, see LICENSE for more details.
"""
import re
import logging
from collections.abc import Iterable
from datetime import timedelta
from six import string_types
from flask import request, current_app, make_response
from werkzeug.datastructures import Headers, MultiDict
from functools import update_wrapper

LOG = logging.getLogger(__name__)

# Response Headers
ACL_ORIGIN = 'Access-Control-Allow-Origin'
ACL_METHODS = 'Access-Control-Allow-Methods'
ACL_ALLOW_HEADERS = 'Access-Control-Allow-Headers'
ACL_EXPOSE_HEADERS = 'Access-Control-Expose-Headers'
ACL_CREDENTIALS = 'Access-Control-Allow-Credentials'
ACL_MAX_AGE = 'Access-Control-Max-Age'

# Request Header
ACL_REQUEST_METHOD = 'Access-Control-Request-Method'
ACL_REQUEST_HEADERS = 'Access-Control-Request-Headers'

ALL_METHODS = ['GET', 'HEAD', 'POST', 'OPTIONS', 'PUT', 'PATCH', 'DELETE']
CONFIG_OPTIONS = ['CORS_ORIGINS', 'CORS_METHODS', 'CORS_ALLOW_HEADERS',
                  'CORS_EXPOSE_HEADERS', 'CORS_SUPPORTS_CREDENTIALS',
                  'CORS_MAX_AGE', 'CORS_SEND_WILDCARD',
                  'CORS_AUTOMATIC_OPTIONS', 'CORS_VARY_HEADER',
                  'CORS_RESOURCES', 'CORS_INTERCEPT_EXCEPTIONS',
                  'CORS_ALWAYS_SEND']
# Attribute added to request object by decorator to indicate that CORS
# was evaluated, in case the decorator and extension are both applied
# to a view.
FLASK_CORS_EVALUATED = '_FLASK_CORS_EVALUATED'

# Strange, but this gets the type of a compiled regex, which is otherwise not
# exposed in a public API.
RegexObject = type(re.compile(''))
DEFAULT_OPTIONS = dict(origins='*',
                       methods=ALL_METHODS,
                       allow_headers='*',
                       expose_headers=None,
                       supports_credentials=False,
                       max_age=None,
                       send_wildcard=False,
                       automatic_options=True,
                       vary_header=True,
                       resources=r'/*',
                       intercept_exceptions=True,
                       always_send=True)


def parse_resources(resources):
    if isinstance(resources, dict):
        # To make the API more consistent with the decorator, allow a
        # resource of '*', which is not actually a valid regexp.
        resources = [(re_fix(k), v) for k, v in resources.items()]

        # Sort by regex length to provide consistency of matching and
        # to provide a proxy for specificity of match. E.G. longer
        # regular expressions are tried first.
        def pattern_length(pair):
            maybe_regex, _ = pair
            return len(get_regexp_pattern(maybe_regex))

        return sorted(resources,
                      key=pattern_length,
                      reverse=True)

    elif isinstance(resources, string_types):
        return [(re_fix(resources), {})]

    elif isinstance(resources, Iterable):
        return [(re_fix(r), {}) for r in resources]

    # Type of compiled regex is not part of the public API. Test for this
    # at runtime.
    elif isinstance(resources,  RegexObject):
        return [(re_fix(resources), {})]

    else:
        raise ValueError("Unexpected value for resources argument.")


def get_regexp_pattern(regexp):
    """
    Helper that returns regexp pattern from given value.

    :param regexp: regular expression to stringify
    :type regexp: _sre.SRE_Pattern or str
    :returns: string representation of given regexp pattern
    :rtype: str
    """
    try:
        return regexp.pattern
    except AttributeError:
        return str(regexp)


def get_cors_origins(options, request_origin):
    origins = options.get('origins')
    wildcard = r'.*' in origins

    # If the Origin header is not present terminate this set of steps.
    # The request is outside the scope of this specification.-- W3Spec
    if request_origin:
        LOG.debug("CORS request received with 'Origin' %s", request_origin)

        # If the allowed origins is an asterisk or 'wildcard', always match
        if wildcard and options.get('send_wildcard'):
            LOG.debug("Allowed origins are set to '*'. Sending wildcard CORS header.")
            return ['*']
        # If the value of the Origin header is a case-sensitive match
        # for any of the values in list of origins
        elif try_match_any(request_origin, origins):
            LOG.debug("The request's Origin header matches. Sending CORS headers.", )
            # Add a single Access-Control-Allow-Origin header, with either
            # the value of the Origin header or the string "*" as value.
            # -- W3Spec
            return [request_origin]
        else:
            LOG.debug("The request's Origin header does not match any of allowed origins.")
            return None


    elif options.get('always_send'):
        if wildcard:
            # If wildcard is in the origins, even if 'send_wildcard' is False,
            # simply send the wildcard. Unless supports_credentials is True,
            # since that is forbidded by the spec..
            # It is the most-likely to be correct thing to do (the only other
            # option is to return nothing, which  almost certainly not what
            # the developer wants if the '*' origin was specified.
            if options.get('supports_credentials'):
                return None
            else:
                return ['*']
        else:
            # Return all origins that are not regexes.
            return sorted([o for o in origins if not probably_regex(o)])

    # Terminate these steps, return the original request untouched.
    else:
        LOG.debug("The request did not contain an 'Origin' header. This means the browser or client did not request CORS, ensure the Origin Header is set.")
        return None


def get_allow_headers(options, acl_request_headers):
    if acl_request_headers:
        request_headers = [h.strip() for h in acl_request_headers.split(',')]

        # any header that matches in the allow_headers
        matching_headers = filter(
            lambda h: try_match_any(h, options.get('allow_headers')),
            request_headers
        )

        return ', '.join(sorted(matching_headers))

    return None


def get_cors_headers(options, request_headers, request_method):
    origins_to_set = get_cors_origins(options, request_headers.get('Origin'))
    headers = MultiDict()

    if not origins_to_set:  # CORS is not enabled for this route
        return headers

    for origin in origins_to_set:
        headers.add(ACL_ORIGIN, origin)

    headers[ACL_EXPOSE_HEADERS] = options.get('expose_headers')

    if options.get('supports_credentials'):
        headers[ACL_CREDENTIALS] = 'true'  # case sensative

    # This is a preflight request
    # http://www.w3.org/TR/cors/#resource-preflight-requests
    if request_method == 'OPTIONS':
        acl_request_method = request_headers.get(ACL_REQUEST_METHOD, '').upper()

        # If there is no Access-Control-Request-Method header or if parsing
        # failed, do not set any additional headers
        if acl_request_method and acl_request_method in options.get('methods'):

            # If method is not a case-sensitive match for any of the values in
            # list of methods do not set any additional headers and terminate
            # this set of steps.
            headers[ACL_ALLOW_HEADERS] = get_allow_headers(options, request_headers.get(ACL_REQUEST_HEADERS))
            headers[ACL_MAX_AGE] = options.get('max_age')
            headers[ACL_METHODS] = options.get('methods')
        else:
            LOG.info("The request's Access-Control-Request-Method header does not match allowed methods. CORS headers will not be applied.")

    # http://www.w3.org/TR/cors/#resource-implementation
    if options.get('vary_header'):
        # Only set header if the origin returned will vary dynamically,
        # i.e. if we are not returning an asterisk, and there are multiple
        # origins that can be matched.
        if headers[ACL_ORIGIN] == '*':
            pass
        elif (len(options.get('origins')) > 1 or
              len(origins_to_set) > 1 or
              any(map(probably_regex, options.get('origins')))):
            headers.add('Vary', 'Origin')

    return MultiDict((k, v) for k, v in headers.items() if v)


def set_cors_headers(resp, options):
    """
    Performs the actual evaluation of Flask-CORS options and actually
    modifies the response object.

    This function is used both in the decorator and the after_request
    callback
    """

    # If CORS has already been evaluated via the decorator, skip
    if hasattr(resp, FLASK_CORS_EVALUATED):
        LOG.debug('CORS have been already evaluated, skipping')
        return resp

    # Some libraries, like OAuthlib, set resp.headers to non Multidict
    # objects (Werkzeug Headers work as well). This is a problem because
    # headers allow repeated values.
    if (not isinstance(resp.headers, Headers)
           and not isinstance(resp.headers, MultiDict)):
        resp.headers = MultiDict(resp.headers)

    headers_to_set = get_cors_headers(options, request.headers, request.method)

    LOG.debug('Settings CORS headers: %s', str(headers_to_set))

    for k, v in headers_to_set.items():
        resp.headers.add(k, v)

    return resp

def probably_regex(maybe_regex):
    if isinstance(maybe_regex, RegexObject):
        return True
    else:
        common_regex_chars = ['*', '\\', ']', '?', '$', '^', '[', ']', '(', ')']
        # Use common characters used in regular expressions as a proxy
        # for if this string is in fact a regex.
        return any((c in maybe_regex for c in common_regex_chars))

def re_fix(reg):
    """
        Replace the invalid regex r'*' with the valid, wildcard regex r'/.*' to
        enable the CORS app extension to have a more user friendly api.
    """
    return r'.*' if reg == r'*' else reg


def try_match_any(inst, patterns):
    return any(try_match(inst, pattern) for pattern in patterns)


def try_match(request_origin, maybe_regex):
    """Safely attempts to match a pattern or string to a request origin."""
    if isinstance(maybe_regex, RegexObject):
        return re.match(maybe_regex, request_origin)
    elif probably_regex(maybe_regex):
        return re.match(maybe_regex, request_origin, flags=re.IGNORECASE)
    else:
        try:
            return request_origin.lower() == maybe_regex.lower()
        except AttributeError:
            return request_origin == maybe_regex


def get_cors_options(appInstance, *dicts):
    """
    Compute CORS options for an application by combining the DEFAULT_OPTIONS,
    the app's configuration-specified options and any dictionaries passed. The
    last specified option wins.
    """
    options = DEFAULT_OPTIONS.copy()
    options.update(get_app_kwarg_dict(appInstance))
    return serialize_options(options)


def get_app_kwarg_dict(appInstance=None):
    """Returns the dictionary of CORS specific app configurations."""
    app = (appInstance or current_app)

    # In order to support blueprints which do not have a config attribute
    app_config = getattr(app, 'config', {})

    return {
        k.lower().replace('cors_', ''): app_config.get(k)
        for k in CONFIG_OPTIONS
        if app_config.get(k) is not None
    }


def flexible_str(obj):
    """
    A more flexible str function which intelligently handles stringifying
    strings, lists and other iterables. The results are lexographically sorted
    to ensure generated responses are consistent when iterables such as Set
    are used.
    """
    if obj is None:
        return None
    elif(not isinstance(obj, string_types)
            and isinstance(obj, Iterable)):
        return ', '.join(str(item) for item in sorted(obj))
    else:
        return str(obj)


def serialize_option(options_dict, key, upper=False):
    if key in options_dict:
        value = flexible_str(options_dict[key])
        options_dict[key] = value.upper() if upper else value


def ensure_iterable(inst):
    """
    Wraps scalars or string types as a list, or returns the iterable instance.
    """
    if isinstance(inst, string_types):
        return [inst]
    elif not isinstance(inst, Iterable):
        return [inst]
    else:
        return inst

def sanitize_regex_param(param):
    return [re_fix(x) for x in ensure_iterable(param)]


def serialize_options(opts):
    """
    A helper method to serialize and processes the options dictionary.
    """
    options = (opts or {}).copy()

    for key in opts.keys():
        if key not in DEFAULT_OPTIONS:
            LOG.warning("Unknown option passed to Flask-CORS: %s", key)

    options['origins'] = sanitize_regex_param(options.get('origins'))
    options['allow_headers'] = sanitize_regex_param(options.get('allow_headers'))

    if r'.*' in options['origins'] and options['supports_credentials'] and options['send_wildcard']:
        raise ValueError("Cannot use supports_credentials in conjunction with"
                         "an origin string of '*'. See: "
                         "http://www.w3.org/TR/cors/#resource-requests")



    serialize_option(options, 'expose_headers')
    serialize_option(options, 'methods', upper=True)

    if isinstance(options.get('max_age'), timedelta):
        options['max_age'] = str(int(options['max_age'].total_seconds()))

    return options

import flask
from flask import request
from urllib.parse import unquote_plus

class CORS(object):
    """
    Initializes Cross Origin Resource sharing for the application. The
    arguments are identical to :py:func:`cross_origin`, with the addition of a
    `resources` parameter. The resources parameter defines a series of regular
    expressions for resource paths to match and optionally, the associated
    options to be applied to the particular resource. These options are
    identical to the arguments to :py:func:`cross_origin`.
    The settings for CORS are determined in the following order
    1. Resource level settings (e.g when passed as a dictionary)
    2. Keyword argument settings
    3. App level configuration settings (e.g. CORS_*)
    4. Default settings
    Note: as it is possible for multiple regular expressions to match a
    resource path, the regular expressions are first sorted by length,
    from longest to shortest, in order to attempt to match the most
    specific regular expression. This allows the definition of a
    number of specific resource options, with a wildcard fallback
    for all other resources.
    :param resources:
        The series of regular expression and (optionally) associated CORS
        options to be applied to the given resource path.
        If the argument is a dictionary, it's keys must be regular expressions,
        and the values must be a dictionary of kwargs, identical to the kwargs
        of this function.
        If the argument is a list, it is expected to be a list of regular
        expressions, for which the app-wide configured options are applied.
        If the argument is a string, it is expected to be a regular expression
        for which the app-wide configured options are applied.
        Default : Match all and apply app-level configuration
    :type resources: dict, iterable or string
    :param origins:
        The origin, or list of origins to allow requests from.
        The origin(s) may be regular expressions, case-sensitive strings,
        or else an asterisk.
        :note: origins must include the schema and the port (if not port 80),
        e.g.,
        `CORS(app, origins=["http://localhost:8000", "https://example.com"])`.
        Default : '*'
    :type origins: list, string or regex
    :param methods:
        The method or list of methods which the allowed origins are allowed to
        access for non-simple requests.
        Default : [GET, HEAD, POST, OPTIONS, PUT, PATCH, DELETE]
    :type methods: list or string
    :param expose_headers:
        The header or list which are safe to expose to the API of a CORS API
        specification.
        Default : None
    :type expose_headers: list or string
    :param allow_headers:
        The header or list of header field names which can be used when this
        resource is accessed by allowed origins. The header(s) may be regular
        expressions, case-sensitive strings, or else an asterisk.
        Default : '*', allow all headers
    :type allow_headers: list, string or regex
    :param supports_credentials:
        Allows users to make authenticated requests. If true, injects the
        `Access-Control-Allow-Credentials` header in responses. This allows
        cookies and credentials to be submitted across domains.
        :note: This option cannot be used in conjunction with a '*' origin
        Default : False
    :type supports_credentials: bool
    :param max_age:
        The maximum time for which this CORS request maybe cached. This value
        is set as the `Access-Control-Max-Age` header.
        Default : None
    :type max_age: timedelta, integer, string or None
    :param send_wildcard: If True, and the origins parameter is `*`, a wildcard
        `Access-Control-Allow-Origin` header is sent, rather than the
        request's `Origin` header.
        Default : False
    :type send_wildcard: bool
    :param vary_header:
        If True, the header Vary: Origin will be returned as per the W3
        implementation guidelines.
        Setting this header when the `Access-Control-Allow-Origin` is
        dynamically generated (e.g. when there is more than one allowed
        origin, and an Origin than '*' is returned) informs CDNs and other
        caches that the CORS headers are dynamic, and cannot be cached.
        If False, the Vary header will never be injected or altered.
        Default : True
    :type vary_header: bool
    """

    def __init__(self, app=None, **kwargs):
        self._options = kwargs
        if app is not None:
            self.init_app(app, **kwargs)

    def init_app(self, app, **kwargs):
        # The resources and options may be specified in the App Config, the CORS constructor
        # or the kwargs to the call to init_app.
        options = get_cors_options(app, self._options, kwargs)

        # Flatten our resources into a list of the form
        # (pattern_or_regexp, dictionary_of_options)
        resources = parse_resources(options.get('resources'))

        # Compute the options for each resource by combining the options from
        # the app's configuration, the constructor, the kwargs to init_app, and
        # finally the options specified in the resources dictionary.
        resources = [
                     (pattern, get_cors_options(app, options, opts))
                     for (pattern, opts) in resources
                    ]

        # Create a human readable form of these resources by converting the compiled
        # regular expressions into strings.
        resources_human = {get_regexp_pattern(pattern): opts for (pattern,opts) in resources}
        LOG.debug("Configuring CORS with resources: %s", resources_human)

        cors_after_request = make_after_request_function(resources)
        app.after_request(cors_after_request)

        # Wrap exception handlers with cross_origin
        # These error handlers will still respect the behavior of the route
        if options.get('intercept_exceptions', True):
            def _after_request_decorator(f):
                def wrapped_function(*args, **kwargs):
                    return cors_after_request(app.make_response(f(*args, **kwargs)))
                return wrapped_function

            if hasattr(app, 'handle_exception'):
                app.handle_exception = _after_request_decorator(
                    app.handle_exception)
                app.handle_user_exception = _after_request_decorator(
                    app.handle_user_exception)

def make_after_request_function(resources):
    def cors_after_request(resp):
        # If CORS headers are set in a view decorator, pass
        if resp.headers is not None and resp.headers.get(ACL_ORIGIN):
            LOG.debug('CORS have been already evaluated, skipping')
            return resp
        normalized_path = unquote_plus(request.path)
        for res_regex, res_options in resources:
            if try_match(normalized_path, res_regex):
                LOG.debug("Request to '%s' matches CORS resource '%s'. Using options: %s",
                      request.path, get_regexp_pattern(res_regex), res_options)
                set_cors_headers(resp, res_options)
                break
        else:
            LOG.debug('No CORS rule matches')
        return resp
    return cors_after_request

def fix_cors(f, **kwargs):
    if type(f) == flask.app.Flask:
        return CORS(**kwargs)
    f.required_methods = {"OPTIONS"}
    f.provide_automatic_options = False

    def wrapped_function(*args, **kwargs):
        _options = kwargs
        options = get_cors_options(current_app, {})
        if options.get('automatic_options') and request.method == 'OPTIONS':
            resp = current_app.make_default_options_response()
        else:
            resp = make_response(f(*args, **kwargs))

        set_cors_headers(resp, options)
        setattr(resp, FLASK_CORS_EVALUATED, True)
        return resp

    return update_wrapper(wrapped_function, f)

LOG.addHandler(logging.NullHandler())

if LOG.level == logging.NOTSET:
    LOG.setLevel(logging.WARN)