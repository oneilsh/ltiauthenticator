import time

from traitlets import Bool, Dict, Unicode, CRegExp, List
from tornado import gen, web

from jupyterhub.auth import Authenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join

from oauthlib.oauth1.rfc5849 import signature
from collections import OrderedDict

import re
import sys

__version__ = '0.4.1.dev'

class LTILaunchValidator:
    # Record time when process starts, so we can reject requests made
    # before this
    PROCESS_START_TIME = int(time.time())

    # Keep a class-wide, global list of nonces so we can detect & reject
    # replay attacks. This possibly makes this non-threadsafe, however.
    nonces = OrderedDict()

    def __init__(self, consumers):
        self.consumers = consumers

    def validate_launch_request(
            self,
            launch_url,
            headers,
            args
    ):
        """
        Validate a given launch request

        launch_url: Full URL that the launch request was POSTed to
        headers: k/v pair of HTTP headers coming in with the POST
        args: dictionary of body arguments passed to the launch_url
            Must have the following keys to be valid:
                oauth_consumer_key, oauth_timestamp, oauth_nonce,
                oauth_signature
        """

        # Validate args!
        if 'oauth_consumer_key' not in args:
            raise web.HTTPError(401, "oauth_consumer_key missing")
        if args['oauth_consumer_key'] not in self.consumers:
            raise web.HTTPError(401, "oauth_consumer_key not known")

        if 'oauth_signature' not in args:
            raise web.HTTPError(401, "oauth_signature missing")
        if 'oauth_timestamp' not in args:
            raise web.HTTPError(401, 'oauth_timestamp missing')

        # Allow 30s clock skew between LTI Consumer and Provider
        # Also don't accept timestamps from before our process started, since that could be
        # a replay attack - we won't have nonce lists from back then. This would allow users
        # who can control / know when our process restarts to trivially do replay attacks.
        oauth_timestamp = int(float(args['oauth_timestamp']))
        if (
                int(time.time()) - oauth_timestamp > 30
                or oauth_timestamp < LTILaunchValidator.PROCESS_START_TIME
        ):
            raise web.HTTPError(401, "oauth_timestamp too old")

        if 'oauth_nonce' not in args:
            raise web.HTTPError(401, 'oauth_nonce missing')
        if (
                oauth_timestamp in LTILaunchValidator.nonces
                and args['oauth_nonce'] in LTILaunchValidator.nonces[oauth_timestamp]
        ):
            raise web.HTTPError(401, "oauth_nonce + oauth_timestamp already used")
        LTILaunchValidator.nonces.setdefault(oauth_timestamp, set()).add(args['oauth_nonce'])


        args_list = []
        for key, values in args.items():
            if type(values) is list:
                args_list += [(key, value) for value in values]
            else:
                args_list.append((key, values))

        base_string = signature.signature_base_string(
            'POST',
            signature.base_string_uri(launch_url),
            signature.normalize_parameters(
                signature.collect_parameters(body=args_list, headers=headers)
            )
        )

        consumer_secret = self.consumers[args['oauth_consumer_key']]

        sign = signature.sign_hmac_sha1(base_string, consumer_secret, None)
        is_valid = signature.safe_string_equals(sign, args['oauth_signature'])

        if not is_valid:
            raise web.HTTPError(401, "Invalid oauth_signature")

        return True


class LTIAuthenticator(Authenticator):
    """
    JupyterHub Authenticator for use with LTI based services (EdX, Canvas, etc)
    """

    auto_login = True
    login_service = 'LTI'

    consumers = Dict(
        {},
        config=True,
        help="""
        A dict of consumer keys mapped to consumer secrets for those keys.

        Allows multiple consumers to securely send users to this JupyterHub
        instance.
        """
    )

    user_admin_roles = List(
        None,
        allow_none=True,
        config=True,
        help="""
        A list of LTI roles that designate admin priveledges. 

        'roles' are interrogated, and each specified entry is matched against
        the suffix of the returned roles. For example, roles as returned by LTI may be 'Instructor', using

        c.LTIAuthenticator.user_admin_roles = ['Instructor', 'TA']

        results in user.admin being set to True via match against the suffix of the first and third listed roles. 
        Longer suffixes can be used, as in ['instrole:ims/lis/Instructor'] to require that role specification (matching only the first). 
        """
    )


    user_id_regexes = List(
        trait=CRegExp,
        None,
        allow_none=True,
        config=True,
        help="""
        Regexes with capture group (one each) to extract username from user_id_keys.
        See help for user_id_keys for more complete examples.
        
        c.LTIAuthenticator.user_id_regex = ["(^[^@]+)@.+"]
        
        This option is only used when user_id_key is set.
        """
    )

    user_id_keys = List(
        trait=Unicode,
        None,
        allow_none=True,
        config=True,
        help="""
        List of keys potentially present in LTI launch info to be used as username.


        Common options are:
          - User's custom canvas login id: ["custom_canvas_user_login_id"]
          - User's email address: ["lis_person_contact_email_primary"]
          - Anonymized user id: ["user_id"]

        It may be that your LMS provides a key for some users, but not others. For example, 'normal' users may have an 
        entry for custom_canvas_user_login_id, but those coming from social logins may not. Use a list of entries to check for in order:
        ["custom_canvas_user_login_id", "lis_person_contact_email_primary", "user_id"]

        Each of these will be checked a) for existance, and then b) against entries in user_id_regexes; if the key isn't present,
        or the value doesn't match the corresponding regex, the check will fall to the next in line. (The length of each list should
        be the same!)

        Repeating entries allows more flexility; in our case custom_canvas_user_login_id is either 1) not set (if the login is a social login),
        2) an email address (normal user login), or 3) a random long hex identifier. For 1), we want to move onto lis_person_contact_email_primary (provided by social login),
        for 2) we want to extract what is before the @, and for 3) we just want to grab the first 6 characters to keep the username short.

        Here's the recipe for that:

        c.LTIAuthenticator.user_id_keys = ["custom_canvas_user_login_id", "custom_canvas_user_login_id", "lis_person_contact_email_primary"]
        c.LTIAuthenticator.user_id_regexes = ["(^[^@]+)@.+", "(^[0-9a-f]{6,6})[0-9a-f]*$", "(^[^@]+)@.+"]

        user_id (which is a randomized user id and should always be present (right?)) is used as a fallback with ".*". 

        Your LMS (Canvas / EdX / whatever) might provide additional
        keys in the LTI launch that you can use. Usually these are
        prefixed with custom_.

        When the default of 'None' is set, the following backwards
        compatible behavior is provided:

          If `canvas_custom_user_id` is present, that is used. Otherwise,
          the anonymized `user_id` is.
        """
    )
    def get_handlers(self, app):
        return [
            ('/lti/launch', LTIAuthenticateHandler)
        ]


    @gen.coroutine
    def authenticate(self, handler, data=None):
        # FIXME: Run a process that cleans up old nonces every other minute
        validator = LTILaunchValidator(self.consumers)

        args = {}
        for k, values in handler.request.body_arguments.items():
            args[k] = values[0].decode() if len(values) == 1 else [v.decode() for v in values]

        # handle multiple layers of proxied protocol (comma separated) and take the outermost
        if 'x-forwarded-proto' in handler.request.headers:
            # x-forwarded-proto might contain comma delimited values
            # left-most value is the one sent by original client
            hops = [h.strip() for h in handler.request.headers['x-forwarded-proto'].split(',')]
            protocol = hops[0]
        else:
            protocol = handler.request.protocol

        launch_url = protocol + "://" + handler.request.host + handler.request.uri

        if validator.validate_launch_request(
                launch_url,
                handler.request.headers,
                args
        ):
            if self.user_id_keys and self.user_id_regexes:
                if len(self.user_id_keys) == len(self.user_id_regexes):
                    ## ensure user_id is used as a fallback
                    self.user_id_keys.append("user_id")
                    self.user_id_regexes.append(".*")
                    # for each potential key/regex match...
                    for i in range(0, len(self.user_id_keys)):
                        user_id_key = self.user_id_keys[i]
                        user_id_regex = self.user_id_regexes[i]
                        # if the key is in the results...
                        if user_id_key in args:
                            given_id = args[user_id_key]
                            match_groups = re.match(user_id_regex, given_id).groups()
                            # and it matches the first capture group...
                            if len(match_groups) > 0:
                                # set the user_id to the capture group and exit the loop
                                user_id = match_groups[0]
                                break    # ugh, break
            else:
                # Backwards compatible behavior, since we don't want hubs to have to
                # migrate usernames.
                # Before we return lti_user_id, check to see if a canvas_custom_user_id was sent.
                # If so, this indicates two things:
                # 1. The request was sent from Canvas, not edX
                # 2. The request was sent from a Canvas course not running in anonymous mode
                # If this is the case we want to use the canvas ID to allow grade returns through the Canvas API
                # If Canvas is running in anonymous mode, we'll still want the 'user_id' (which is the `lti_user_id``)
                user_id = args.get('custom_canvas_user_id', args['user_id'])

            is_admin = False
            if self.user_admin_roles:
                sys.stderr.write("Checking query roles: " + str(self.user_admin_roles) + "\n")
                for role_query in self.user_admin_roles:

                    roles = args.get('roles', None)
                    if roles:
                        sys.stderr.write("... against roles: " + str(roles) + "\n")
                        for role in roles.split(","):
                            if role.endswith(role_query):
                                is_admin = True

            return {
                'name': user_id,
                'admin': is_admin,
                'auth_state': {k: v for k, v in args.items() if not k.startswith('oauth_')}
            }


    def login_url(self, base_url):
        return url_path_join(base_url, '/lti/launch')


class LTIAuthenticateHandler(BaseHandler):
    """
    Handler for /lti/launch

    Implements v1 of the LTI protocol for passing authentication information
    through.

    If there's a custom parameter called 'next', will redirect user to
    that URL after authentication. Else, will send them to /home.
    """

    @gen.coroutine
    def post(self):
        """
        Technical reference of relevance to understand this function
        ------------------------------------------------------------
        1. Class dependencies
           - jupyterhub.handlers.BaseHandler: https://github.com/jupyterhub/jupyterhub/blob/abb93ad799865a4b27f677e126ab917241e1af72/jupyterhub/handlers/base.py#L69
           - tornado.web.RequestHandler: https://www.tornadoweb.org/en/stable/web.html#tornado.web.RequestHandler
        2. Function dependencies
           - login_user: https://github.com/jupyterhub/jupyterhub/blob/abb93ad799865a4b27f677e126ab917241e1af72/jupyterhub/handlers/base.py#L696-L715
             login_user is defined in the JupyterHub wide BaseHandler class,
             mainly wraps a call to the authenticate function and follow up.
             a successful authentication with a call to auth_to_user that
             persists a JupyterHub user and returns it.
           - get_next_url: https://github.com/jupyterhub/jupyterhub/blob/abb93ad799865a4b27f677e126ab917241e1af72/jupyterhub/handlers/base.py#L587
           - get_body_argument: https://www.tornadoweb.org/en/stable/web.html#tornado.web.RequestHandler.get_body_argument
        """
        # FIXME: Figure out if we want to pass the user returned from
        #        self.login_user() to self.get_next_url(). It is named
        #        _ for now as pyflakes is fine about having an unused
        #        variable named _.
        _ = yield self.login_user()
        next_url = self.get_next_url()
        body_argument = self.get_body_argument(
            name='custom_next',
            default=next_url,
        )

        self.redirect(body_argument)
