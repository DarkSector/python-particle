import datetime
import pytz
import dateutil.parser
import requests
from requests.auth import HTTPBasicAuth


class TokenException(Exception):
    def __init__(self, message, errors=None):
        super(TokenException, self).__init__(message)
        self.errors = errors


class Particle(object):
    """
        This the Cloud class that is directly associated with the Particle API
        It has the following functions:
            - Acquire a new token
            - Get token info
            - Get token list
            - Delete Token

    """
    API_PREFIX = 'https://api.particle.io'
    API_VERSION = '/v1/'

    token_list = None
    token = None  # this is the token object;
    refresh_token = None
    expires_at = None
    time_acquired = None

    session = None

    username = None
    password = None

    def __init__(self, username, password):
        self.username = username
        self.password = password
        token_dict = self.get_valid_token()
        self.token = token_dict['token']
        self.expires_at = token_dict['expiry']
        super(Particle, self).__init__()

    def get_valid_token(self):
        token_list = self.get_token_list()
        token = self.get_valid_token_from_list(token_list)
        if not token:
            return self.standardize(self.get_new_token())
        self.token_list = token_list
        return self.standardize(token)

    def get_new_token(self):
        url = self.API_PREFIX + '/oauth/token'
        payload = {'username': self.username,
                   'password': self.password,
                   'grant_type': 'password', }
        token_response = requests.post(url, auth=('particle', 'particle'), data=payload)
        if token_response.ok:
            data = token_response.json()
            self.token_list = self.get_token_list()
            return data
        else:
            raise TokenException(token_response.reason)

    def get_valid_token_from_list(self, token_list):
        new_list = []
        for token in token_list:
            if self.token_date_is_valid(token) and self.token_is_password_only(token):
                new_list.append((token, dateutil.parser.parse(token['expires_at']),))
        sorted_list = sorted(new_list, key=lambda i: i[1], reverse=True)
        token = sorted_list[0][0]
        return token if token else None

    def token_date_is_valid(self, token):
        if token['expires_at']:
            token_date = dateutil.parser.parse(token['expires_at'])
            return True if token_date > datetime.datetime.now(pytz.utc) else False
        return False

    def token_is_password_only(self, token):
        if token['client'] == "__PASSWORD_ONLY__":
            return True
        return False

    def get_token_list(self):
        url = self.API_PREFIX + self.API_VERSION + 'access_tokens'
        tokens = requests.get(url, auth=HTTPBasicAuth(self.username, self.password))
        if tokens.ok:
            return tokens.json()
        else:
            return None

    def standardize(self, token_dict):
        standard_dict = {}
        try:
            _token = token_dict['token']
        except KeyError:
            _token = token_dict['access_token']
            _expiry = dateutil.parser.parse(self.get_token_expiry_from_list(_token))
        else:
            _expiry = dateutil.parser.parse(token_dict['expires_at'])

        standard_dict.update({
            'token': _token,
            'expiry': _expiry,
        })
        return standard_dict

    def get_token_expiry_from_list(self, token_value):
        _expiry = None
        for t in self.token_list:
            if t['token'] == token_value:
                _expiry = dateutil.parser.parse(t['expires_at'])
                break
        return _expiry

    def current_token_is_valid(self):
        if self.expires_at > datetime.datetime.now(pytz.utc):
            return True
        return False

    def get_session(self):
        if not self.session:
            self.session = requests.session()

        if self.current_token_is_valid():
                self.session.headers.update({
                    'Authorization': "Bearer %s" % self.token,
                })
        else:
            raise TokenException("Token has expired, please re instantiate the class")
        return self.session

    def get_api_prefix(self):
        return "%s" % self.API_PREFIX + self.API_VERSION

    def get_device_list(self):
        url = self.get_api_prefix() + 'devices'
        session = self.get_session()
        # session = requests.session()
        device_list = session.get(url)
        if device_list.ok and device_list.status_code == 200:
            return device_list.json()
        else:
            TokenException(device_list.reason, device_list.status_code)

    def get_device_info(self, device_serial):
        url = self.get_api_prefix() + 'devices/%s' % device_serial
        session = self.get_session()
        response = session.get(url)
        if response.ok and response.status_code == 200:
            return response.json()
        return None

    def claim_device(self, device_serial):
        url = self.get_api_prefix() + 'devices/'
        session = self.get_session()
        response = session.post(url, data={"id": device_serial})
        if response.ok and response.status_code == 200:
            return True
        else:
            return False

    def get_variable(self, device_serial, variable_name):
        url = self.get_api_prefix() + 'devices/%s/%s' % (device_serial, variable_name)
        session = self.get_session()
        response = session.get(url)
        if response.ok and response.status_code == 200:
            return response.json()
        return None