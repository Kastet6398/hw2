"""
Test for library.py
"""

# Import necessary libraries
import random  # `random` for random generations
import string  # `string` for accessing all characters and punctuations

import pytest  # `pytest` for testing

import library  # `library` for testing its functions

# Payloads to test
payloads = [
    [
        {
            "number1": random.randint(0, 100000),  # Example number
            "number2": random.randint(0, 100000),  # Example number
            "number3": random.randint(0, 100000)  # Example number
        },
        '.'.join(random.choices(string.ascii_letters + string.digits, k=1000))  # Secret key
    ]
    for i in range(1000)  # Do those operations 1000 times
]


# Use pytest to test multiple payloads in one function
@pytest.mark.parametrize('payload, key', payloads)
def test_encrypt_decrypt(payload: dict, key: str):
    # Encrypt payload
    jwt_token = library.generate_jwt_token(payload, key)
    # Decrypt the token
    decrypted_data = library.decrypt_jwt_token(jwt_token, key)
    # Delete `exp` and `iat`
    del decrypted_data['exp'], decrypted_data['iat'], payload['exp'], payload['iat']
    print(decrypted_data, payload)
    # Check if decrypted data equals to input token
    assert decrypted_data == payload


@pytest.mark.parametrize('payload, key', payloads)
def test_invalid_token(payload: dict, key: str):
    # Encrypt payload
    jwt_token = library.generate_jwt_token(payload, key)
    # Default value for incorrect key
    incorrect_key = key
    # Generate an incorrect key
    while incorrect_key == key:  # While incorrect key is correct
        # Generate a random key
        incorrect_key = ''.join(random.choices(string.ascii_letters + string.digits, k=1000))
    # Decrypt the token
    decrypted_data = library.decrypt_jwt_token(jwt_token, incorrect_key)
    # Check if decrypted data equals to input token
    assert decrypted_data == "INVALID SIGNATURE ERROR: Signature verification failed"


@pytest.mark.parametrize('payload, key', payloads)
def test_decode_error(payload: dict, key: str):
    # Encrypt payload
    jwt_token = library.generate_jwt_token(payload, key)
    # Generate token with invalid characters
    incorrect_jwt_token = jwt_token + random.choice(
        ["\t", "\r", "\f", "\a", "\b", "\n", "\v", "\1", "\2", "\3", "\4", "\5", "\6", "\7", "\0"])
    # Decrypt the incorrect token
    decrypted_data = library.decrypt_jwt_token(incorrect_jwt_token, key)
    # Check if decrypted data equals to input token
    assert decrypted_data == "DECODE ERROR: Invalid crypto padding"


@pytest.mark.parametrize('payload, key', payloads)
def test_not_enough_segments(payload: dict, key: str):
    # Generate token with one character
    incorrect_jwt_token = random.choice(string.ascii_letters + string.digits)
    # Decrypt the incorrect token
    decrypted_data = library.decrypt_jwt_token(incorrect_jwt_token, key)
    # Check if decrypted data equals to input token
    assert decrypted_data == "DECODE ERROR: Not enough segments"
