"""
Library for JWT token encryption and decryption
================================================

This is a library for JWT token encryption and decryption

Author:
    Konstantin Nezhalsky <konstantin.nezhalsky@gmail.com>
"""

# Import necessary libraries
import datetime  # `datetime` for `iat` and `exp` dates

import jwt  # `JWT` for encoding
import pytest  # `pytest` for testing

# All functions present in this library
__all__ = ['generate_jwt_token', 'decrypt_jwt_token']


# Encryption function
def generate_jwt_token(payload: dict, key: str) -> str:
    """
    Encrypt payload using JWT.

    Parameters:
        payload (dict): Dictionary to be encrypted.
        key (str): Secret key.

    Returns:
        str: The generated JWT token.
    """
    # Get current time
    current_time = datetime.datetime.utcnow()
    # Set issued at date (`iat`) for payload
    payload['iat'] = current_time
    # Set expiration date (`exp`) in seconds for payload
    payload['exp'] = current_time + datetime.timedelta(minutes=15)
    # Encode the payload using `jwt.encode(payload, key)` function
    result = jwt.encode(payload, key)
    # Return the result
    return result


# Decryption function
def decrypt_jwt_token(jwt_token: str, key: str) -> dict | str:
    """
    Decrypt payload using JWT.

    Parameters:
        jwt_token (dict): JWT token to be decrypted.
        key (str): Secret key.

    Returns:
        dict | str: Dict if no exception occurred, str otherwise.
    """
    try:
        # Try to decode the given token
        result = jwt.decode(jwt_token, key, "HS256")
    except jwt.ExpiredSignatureError:
        # If the token expired
        # Get the passed time
        seconds_passed = datetime.datetime.utcnow() - datetime.timedelta(
            seconds=jwt.decode(jwt_token, key, "HS256", {"verify_signature": False})["exp"])
        # Set the result to a readable error message
        result = f'EXPIRED SIGNATURE ERROR: {seconds_passed.hour} hour(s) {seconds_passed.minute} \
minute(s) {seconds_passed.second} second(s) passed after expiration time'
    except Exception as exception:
        # If another exception occurs
        # Get the name of occurred exception
        exception_name = exception.__class__.__name__
        # Format the exception name
        exception_name_formatted = ''.join(
            map(lambda char: (" " if char.isupper() and exception_name.index(char) > 0 else "") + char, exception_name))
        # Set the result to a readable error message
        result = f'{exception_name_formatted.upper()}: {exception}'
    # Return the result
    return result


# When run this file
if __name__ == "__main__":
    # Test it
    pytest.main(['-x', 'test_library.py'])
