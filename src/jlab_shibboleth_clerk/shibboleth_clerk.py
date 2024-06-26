import subprocess
import json
import base64
from jupyterhub.auth import Authenticator, LocalAuthenticator
from jupyterhub.handlers import BaseHandler
from traitlets import Unicode, List, validate, TraitError
from tornado import web
from oauthenticator.oauth2 import OAuthLoginHandler
from oauthenticator.oauth2 import OAuthenticator


class ShibbolethClerkLoginHandler(OAuthLoginHandler):

    def _serialize_state(state):
        """Serialize OAuth state to a base64 string after passing through JSON"""
        json_state = json.dumps(state)
        return base64.urlsafe_b64encode(json_state.encode("utf8")).decode("ascii")
    
    def _get_user_data_from_request(self):
        """Get shibboleth attributes (user data) from request headers."""
        user_data = {'shibboleth':False}
        value_list = [self.request.headers.get(header, "") for header in self.authenticator.headers]

        self.log.info("User data debug: %s", (value_list) )

        if value_list[0]:
                user_data['jh_name'] = value_list[0]
                user_data['shibboleth'] = True
        self.log.info("User data debug: %s", user_data)
        return user_data

    async def get(self):
        """Get user data and log user in."""
        self.statsd.incr('login.request')
        user_data = self._get_user_data_from_request()

        if user_data['shibboleth']:
            user = await self.login_user(user_data)
            if user is None:
                raise web.HTTPError(403)
            else:
                self.redirect(self.get_next_url(user))

        else:
            redirect_uri = self.authenticator.get_callback_url(self)
            token_params = self.authenticator.extra_authorize_params.copy()
            self.log.info(f"OAuth redirect: {redirect_uri}")

            state_id = self._generate_state_id()
            next_url = self._get_next_url()

            cookie_state = _serialize_state({"state_id": state_id, "next_url": next_url})
            self.set_state_cookie(cookie_state)

            authorize_state = _serialize_state({"state_id": state_id})
            token_params["state"] = authorize_state
            self.authorize_redirect(
                redirect_uri=redirect_uri,
                client_id=self.authenticator.client_id,
                scope=self.authenticator.scope,
                extra_params=token_params,
                response_type="code",
            )

class ShibbolethClerkLogoutHandler(OAuthLogoutHandler):
    """Log a user out from JupyterHub by clearing their login cookie
    and then redirect to shibboleth logout url to clear shibboleth cookie."""

    async def get(self):
        user = await self.get_current_user()

        self.log.info("User logged out: %s", user.name)
        await self.default_handle_logout()
        await self.handle_logout()
        self._jupyterhub_user = None
        if user.name.startswith('shibboleth'):
            self.redirect(self.authenticator.shibboleth_logout_url)
        else:
            self.redirect(self.authenticator.clerk_logout_url)

class ShibbolethClerkAuthenticator(OAuthenticator):

    manage_groups = False

    headers = List(
        default_value=['mail'],
        config=True,
        help="""List of HTTP headers to get user data. First item is used as unique user name."""
    )
    shibboleth_logout_url = Unicode(
        default_value='',
        config=True,
        help="""Url to logout from shibboleth SP.""")
    
    clerk_logout_url = Unicode(
        default_value='"https://databrix.org"',
        config=True,
        help="""Url to logout from Clerk.""")

    login_handler = ShibbolethClerkLoginHandler
    logout_handler = ShibbolethClerkLogoutHandler

    @validate('headers')
    def _valid_headers(self, proposal):
        if not proposal['value']:
            raise TraitError('Headers should contain at least 1 item.')
        return proposal['value']

    def login_url(self, base_url):
        return url_path_join(base_url, "login")

    async def authenticate(self, handler, data):


        try:
            check = data['shibboleth']
            username = data['jh_name']
            jhname = 'shibboleth-' + username
            user_data = {
                  'name': jhname,
                  'auth_state': data
                  }
            return user_data

        except:
            access_token_params = self.build_access_tokens_request_params(handler, data)
            token_info = await self.get_token_info(handler, access_token_params)
            user_info = await self.token_to_user(token_info)

            username = self.user_info_to_username(user_info)
            username = self.normalize_username(username)

            refresh_token = token_info.get("refresh_token", None)
            if self.enable_auth_state and not refresh_token:
                self.log.debug(
                    "Refresh token was empty, will try to pull refresh_token from previous auth_state"
                )
                refresh_token = await self.get_prev_refresh_token(handler, username)
                if refresh_token:
                    token_info["refresh_token"] = refresh_token

            auth_model = {
                "name": 'clerk-'+username,
                "admin": True if username in self.admin_users else None,
                "auth_state": self.build_auth_state_dict(token_info, user_info)
            }

            return await self.update_auth_model(auth_model)

    def get_handlers(self, app):
        return [ (r'/oauth_callback',self.callback_handler),
                 (r'/logout',self.logout_handler),
                 (r'/login', self.login_handler),
               ]