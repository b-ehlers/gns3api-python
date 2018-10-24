# gns3api - Simple python module to access the GNS3 API

This module provides an easy access to the GNS3 API, see http://api.gns3.net/ .

**Warning**: The module is not yet stable, it may change at any time.

Usage:
- create an API object  
  api = gns3api.GNS3Api()
- access the API  
  data = api.request('POST', '/v2/version', {"version": "0.1"})

Restrictions:
- Notifications are not supported

Requirements:
- Python 2.7 or 3.x
- GNS3 2.x

Installation:

Either copy gns3api.py into the same folder as your program or
install it with `python setup.py install`.

Examples:

`test_api` is a small program to test some basic API calls.

`get_console` is a simple application to get the console port of a node.

`start_nodes` starts the nodes of a project one by one.
