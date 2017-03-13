"""
Access GNS3 controller via API
"""

import configparser
import http.client
import ssl
import json
import os
import sys
from base64 import b64encode

class APIException(http.client.HTTPException):
    def __str__(self):
        return '[Status {}] {}'.format(self.args[0], self.args[1])

class api:

    def __init__(self, proto='http', host=None, port=3080,
                 user=None, passwd=None, verify=True):
        """
        GNS3 API

        :param proto:  Protocol (http/https), default 'http'
        :param host:   Host name or IP, if None the connection parameters
                       are read from the GNS3 configuration file
        :param port;   Port number, default 3080
        :param user:   User name, None for no authentification
        :param passwd: Password
        :param verify: Verify CERT (on https), default True
                       False: no CERT verification
                       True:  verification using the system CA certificates
                       file:  verification using the file and the system CA
        """

        if host is None or host == '':
            (proto, host, port, user, passwd) = api.get_controller_params()

        self.controller = "{}://{}:{}".format(proto, host, port)

        # authentication
        if user is None or user == '':
            self._auth = None
        else:
            if passwd is None:
                passwd = ''
            self._auth = 'Basic ' + \
                b64encode((user+':'+passwd).encode()).decode('ascii')

        # open connection
        if proto == 'http':
            self._conn = http.client.HTTPConnection(host, port, timeout=10)
        elif proto == 'https':
            context = ssl.create_default_context()
            if isinstance(verify, str):
                context.check_hostname = False
                context.load_verify_locations(cafile=verify)
            elif not verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self._conn = http.client.HTTPSConnection(host, port, timeout=10,
                                                     context=context)
        else:
            raise http.client.UnknownProtocol(proto)

        self._conn.connect()

    @staticmethod
    def get_controller_params():
        """
        Returns GNS3 controller connection parameters

        :returns: Tuple of protocol, host, port, user, password
        """

        # find config file
        if sys.platform.startswith('win'):
            fn_conf = os.path.join(os.path.expandvars('%APPDATA%'), 'GNS3',
                                   'gns3_server.ini')
        else:
            fn_conf = os.path.join(os.path.expanduser('~'), '.config', 'GNS3',
                                   'gns3_server.conf')

        # parse config
        config = configparser.ConfigParser()
        try:
            config.read(fn_conf)
            serv_conf = config['Server']
        except (OSError, configparser.Error, KeyError):
            serv_conf = {}

        # extract config variables
        proto = serv_conf.get('protocol', 'http')
        host = serv_conf.get('host', '127.0.0.1')
        port = int(serv_conf.get('port', 3080))
        user = serv_conf.get('user', None)
        passwd = serv_conf.get('password', None)

        return (proto, host, port, user, passwd)

    def request(self, method, path, input=None, timeout=60):
        """
        API request

        :param method:  HTTP method ('GET'/'PUT'/'POST'/'DELETE')
        :param path:    URL path
        :param input:   input data to the API endpoint
        :param timeout: timeout, default 60

        :returns: output data
        """

        # json encode input
        if input is None:
            body = None
        else:
            body = json.dumps(input, separators=(',', ':'))

        # authentication
        headers = {}
        if self._auth is not None:
            headers['Authorization'] = self._auth

        # send request
        if self._conn.timeout != timeout:
            self._conn.timeout = timeout
            if self._conn.sock:
                self._conn.sock.settimeout(timeout)
        self._conn.request(method, path, body, headers=headers)

        # get response
        resp = self._conn.getresponse()
        data = resp.read()
        try:
            output = json.loads(data.decode('utf-8', errors='ignore'))
        except json.decoder.JSONDecodeError:
            output = data

        # check for errors
        if resp.status < 200 or resp.status >= 300:
            try:
                message = output['message']
            except (TypeError, KeyError):
                if data is not None and data != b'':
                    message = data.decode('utf-8', errors='ignore')
                else:
                    message = resp.reason
            raise APIException(resp.status, message)

        return output

    def close(self):
        """
        Closes HTTP(S) connection
        """

        self._conn.close()
