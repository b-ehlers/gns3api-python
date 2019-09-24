"""
Access GNS3 controller via API
"""

import os
import sys
import ssl
import json
from base64 import b64encode

try:
    import configparser
except ImportError:		# fallback to Python 2 module
    import ConfigParser as configparser

try:
    import http.client as http_client
    from urllib.parse import urlsplit
    GNS3BaseException = OSError
except ImportError:		# fallback to Python 2 module
    import httplib as http_client
    from urlparse import urlsplit
    GNS3BaseException = IOError

class GNS3ApiException(GNS3BaseException):
    """
    GNS3 API Exceptions, base class
    """
    def __init__(self, *args):
        super(GNS3ApiException, self).__init__()
        self.args = args

class GNS3ConfigurationError(GNS3ApiException):
    """
    GNS3 configuration error
    """
    def __init__(self, message="Missing/invalid GNS3 configuration"):
        GNS3ApiException.__init__(self, message)

class HTTPClientError(GNS3ApiException):
    """
    HTTP client library error
    """
    def __str__(self):
        return ": ".join(str(x) for x in self.args)

class HTTPError(GNS3ApiException):
    """
    HTTP response error
    """
    def __str__(self):
        if len(self.args) >= 2:
            return '[Status {}] '.format(self.args[0]) + \
                   " ".join(str(x) for x in self.args[1:])
        return str(self.args[0])

class GNS3Api:
    """
    GNS3 API - an API to GNS3
    """

    def __init__(self, url=None, user=None, password=None,
                 profile=None, verify=True):
        """
        GNS3 API

        :param url:      Server URL, if None the connection parameters
                         are read from the GNS3 configuration file
        :param user:     User name, None for no authentification
        :param password: Password
        :param profile:  GNS3 configuration profile
        :param verify:   Verify CERT (on https), default True
                         False: no CERT verification
                         True:  verification using the system CA certificates
                         file:  verification using the file and the system CA
        """

        if not url:
            (url, user, password) = GNS3Api.get_controller_connection(profile)

        # split URL
        try:
            url_tuple = urlsplit(url, "http")
            if not url_tuple.netloc:	# fix missing "//" before host
                url_tuple = urlsplit(url_tuple.scheme + "://" + url_tuple.path)
            proto = url_tuple.scheme
            host = url_tuple.hostname
            port = url_tuple.port or 3080
            if user is None:
                user = url_tuple.username
                if password is None:
                    password = url_tuple.password
        except ValueError as err:
            raise HTTPClientError("UrlError", str(err))
        if host == '0.0.0.0':
            host = '127.0.0.1'
        elif host == '::':
            host = '::1'

        if ':' in host:			# IPv6
            self.controller = "{}://[{}]:{}".format(proto, host, port)
        else:
            self.controller = "{}://{}:{}".format(proto, host, port)
        self.status_code = None

        # authentication
        self._auth = {}
        if user is not None and user != '':
            if password is None:
                password = ''
            self._auth['Authorization'] = 'Basic ' + \
                b64encode((user+':'+password).encode('utf-8')).decode('ascii')

        # open connection
        try:
            if proto == 'http':
                self._conn = http_client.HTTPConnection(host, port, timeout=10)
            elif proto == 'https':
                context = ssl.create_default_context()
                if isinstance(verify, str):
                    context.check_hostname = False
                    context.load_verify_locations(cafile=verify)
                elif not verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                self._conn = http_client.HTTPSConnection(host, port, timeout=10,
                                                         context=context)
            else:
                raise HTTPClientError("UnknownProtocol", proto)

            self._conn.connect()
        except (IOError, OSError, http_client.HTTPException) as err:
            raise HTTPClientError(type(err).__name__, str(err))

    @staticmethod
    def get_controller_settings(profile=None):
        """
        Get GNS3 controller settings

        :param profile: GNS3 configuration profile

        :returns: controller settings
        """

        # find config file
        if sys.platform.startswith('win'):
            fn_conf = os.path.join(os.path.expandvars('%APPDATA%'), 'GNS3')
            if profile and profile != "default":
                fn_conf = os.path.join(fn_conf, 'profiles', profile)
            fn_conf = os.path.join(fn_conf, 'gns3_server.ini')
        else:
            fn_conf = os.path.join(os.path.expanduser('~'), '.config', 'GNS3')
            if profile and profile != "default":
                fn_conf = os.path.join(fn_conf, 'profiles', profile)
            fn_conf = os.path.join(fn_conf, 'gns3_server.conf')

        # parse config
        config = configparser.ConfigParser()
        serv_conf = None
        try:
            if config.read(fn_conf):
                serv_conf = dict(config.items('Server'))
        except (IOError, OSError, configparser.Error) as err:
            raise GNS3ConfigurationError("Error reading GNS3 configuration: {}".format(err))
        if serv_conf is None:
            raise GNS3ConfigurationError("Missing GNS3 configuration file '{}'".format(fn_conf))

        # check for mandatory host key
        if 'host' not in serv_conf:
            raise GNS3ConfigurationError("GNS3 configuration: Missing host")

        return serv_conf

    @staticmethod
    def get_controller_connection(profile=None):
        """
        Get GNS3 controller connection parameters

        :param profile: GNS3 configuration profile

        :returns: Tuple of url, user, password
        """

        serv_conf = GNS3Api.get_controller_settings(profile)

        host = serv_conf['host']
        proto = serv_conf.get('protocol', 'http')
        port = int(serv_conf.get('port', 3080))
        user = serv_conf.get('user', None)
        password = serv_conf.get('password', None)

        # create URL
        if ':' in host:			# IPv6
            url = "{}://[{}]:{}".format(proto, host, port)
        else:
            url = "{}://{}:{}".format(proto, host, port)

        return (url, user, password)

    def request(self, method, path, args=None, timeout=60):
        """
        API request

        :param method:  HTTP method ('GET'/'PUT'/'POST'/'DELETE')
        :param path:    URL path, can be a list or tuple
        :param args:    arguments to the API endpoint
        :param timeout: timeout, default 60

        :returns: result
        """

        # json encode args
        if args is None:
            body = None
        else:
            body = json.dumps(args, separators=(',', ':'))

        # methods are upper case
        method.upper()

        # make path variable to an URL path
        if isinstance(path, (list, tuple)):
            path = "/".join(str(x) for x in path)
        else:
            path = str(path)
        if not path.startswith("/"):
            path = "/" + path

        # send request
        if self._conn.timeout != timeout:
            self._conn.timeout = timeout
            if self._conn.sock:
                self._conn.sock.settimeout(timeout)
        headers = {'Content-Type': 'application/json',
                   'User-Agent': 'GNS3Api'}
        headers.update(self._auth)

        try:
            # send request / get response
            self._conn.request(method, path, body, headers=headers)
            resp = self._conn.getresponse()
            data = resp.read()
            if resp.getheader('Content-Type') == 'application/json':
                result = json.loads(data.decode('utf-8', errors='ignore'))
            else:
                result = data
        except (IOError, OSError, http_client.HTTPException) as err:
            raise HTTPClientError(type(err).__name__, str(err))

        # check for errors
        self.status_code = resp.status
        if self.status_code < 200 or self.status_code >= 300:
            try:
                message = result['message']
            except (TypeError, KeyError):
                if data is not None and data != b'':
                    message = data.decode('utf-8', errors='ignore')
                else:
                    message = resp.reason
            raise HTTPError(self.status_code, message)

        return result

    def close(self):
        """
        Closes HTTP(S) connection
        """

        self._conn.close()
