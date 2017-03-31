# gns3api - Simple python module to access the GNS3 API

This module provides an easy access to the GNS3 API, see http://api.gns3.net/en/2.0 .

**Warning**: The module is not yet stable, it may change at any time.

Example:
- create an API object  
  api = gns3api.GNS3Api()
- access the API  
  data = api.request('POST', '/v2/version', {"version": "0.1"})

Restrictions:
- Notifications are not supported

Requirements:
- Python 3
- GNS3 2.0
