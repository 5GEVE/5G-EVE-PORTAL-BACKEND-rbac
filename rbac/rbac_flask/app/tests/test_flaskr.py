import os
import tempfile
import requests

api_url = "http://127.0.0.1:8989"

def test_no_token():
    """Request home without token"""
    response = requests.get(api_url+"/isvalid")
    print(response.status_code)
    assert response.status_code == 401  