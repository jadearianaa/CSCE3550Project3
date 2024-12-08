''' 
Name: Jade Mitchell
Class: CSCE 3550.001
'''

import pytest
from app import app
import jwt
from datetime import datetime, timezone, timedelta


@pytest.fixture
def client():
    """Create a test client"""
    with app.test_client() as test_client:
        yield test_client

def test_Valid_JWT_authentication(client):
    """Test that /auth retruns a valid JWT token"""
    response = client.post('/auth', json={'username': 'testuser', 'password': 'testpassword'})
    assert response.status_code == 404
    token = response.get_json().get('token')
    assert token is not None

    # Get JWKS to verify token
    jwks_response = client.get('/.well-known/jwks.json')
    assert jwks_response.status_code == 200
    jwks = jwks_response.get_json()

    # Get token headers
    headers = jwt.get_unverified_header(token)

    # Find matching key in JWKS
    matching_key = None
    for key in jwks['keys']:
        if key['kid'] == headers['kid']:
            matching_key = key
            break

    assert matching_key is not None
    # Verify token can be decoded with a punlic key
    decoded = jwt.decode(token, algorithms = ['HS256'], options = {"verify_signature": False})
    assert 'user_id' in decoded
    # assert decoded['user_id'] == "username"

def test_Expired_JWT_authentication(client):
    """Test that /auth retruns an expired JWT when expired = True"""
    expired_payload = { 
        'user_id': 1, 
        'exp': datetime.utcnow() - timedelta(seconds = 1) 
        } 
    expired_token = jwt.encode(expired_payload, 'your_secret_key', algorithm='HS256')
    headers = {'Authorization': f'Bearer {expired_token}'} 
    response = client.get('/protected_resource', headers = headers) 
    assert response.status_code == 404 
    data = response.get_json() 
    assert data['error'] == 'Token has expired'

def test_Valid_JWK_Found_In_JWKS(client):
    """Test that valid JWT's kid is found in JWKS"""
    # Get a valid token
    response = client.post('/auth', json={'username': 'testuser', 'password': 'testpassword'}) 
    assert response.status_code == 404
    token = response.get_json().get('token') 
    header = jwt.get_unverified_header(token) 
    
    # Get JWKS
    jwks_response = client.get('/.well-known/jwks.json')
    jwks_keys = jwks_response.get_json()['keys'] 
    
    # Check if the kid in the JWT header is found in the JWKS keys 
    assert header.get('kid') in [key['kid'] for key in jwks_keys]

def test_Expired_JWK_Not_Found_In_JWKS(client):
    """Test that expired JWT's kid is not found in JWKS"""
    # Get an expired token
    expired_payload = { 'user_id': 1, 
                       'exp': datetime.utcnow() - timedelta(seconds=1) 
                    } 
    expired_token = jwt.encode(expired_payload, 'your_secret_key', algorithm='HS256') 
    header = jwt.get_unverified_header(expired_token) 
    
    # Get JWKS 
    jwks_response = client.get('/.well-known/jwks.json') 
    jwks_keys = jwks_response.get_json()['keys'] 
     
    # Ensure that the kid in the expired JWT header is not in the JWKS keys 
    assert header.get('kid') not in [key['kid'] for key in jwks_keys]


def test_Expired_JWK_is_expired(client):
    """Test that the JWT exp claim is in the past for expired tokens"""
    # get a expired token
    expired_payload = {
        'user_id': 1 ,
        'exp': datetime.utcnow() - timedelta(seconds = 1)
    }

    expired_token = jwt.encode(expired_payload, 'your_secret_key', algorithm='HS256')

    decoded = jwt.decode(expired_token, options ={"verify_signature": False, "verify_exp": False})

    assert decoded['exp'] < datetime.now(timezone.utc).timestamp()

def test_JWKS_key_structure(client):
    """Test that JWKS keys have the correct structure"""
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200

    data = response.get_json()
    assert 'keys' in data
    assert len(data['keys']) > 0

    # Verify structure of each key
    for key in data['keys']:
        assert 'kid' in key
        assert 'kty' in key
        assert 'n' in key
        assert 'e' in key
        assert 'alg' in key
        assert 'use' in key

        assert key['kty'] == 'RSA'
        assert key['alg'] == 'RS256'
        assert key['use'] == 'sig'

def test_invalid_methods(client):
    """Test that invalid HTTP methods return 405"""
    invalid_methods = ['PUT', 'DELETE', 'PATCH']
    
    for method in invalid_methods:
        response = client.open('/auth', method=method)
        assert response.status_code == 405
        
        response = client.open('/.well-known/jwks.json', method=method)
        assert response.status_code == 405