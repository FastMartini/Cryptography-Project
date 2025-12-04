#!/usr/bin/env python3  # Shebang line to indicate Python 3 interpreter

import socket  # Import socket for TCP communication
import hashlib  # Import hashlib for SHA256 hashing
import random  # Import random for RSA helpers
import sys  # Import sys for potential command-line extensions

# =========================
# RSA HELPER FUNCTIONS
# (Same logic as server so they interoperate)
# =========================

def egcd(a, b):  # Extended Euclidean Algorithm
    """Extended Euclidean Algorithm"""  # Docstring
    if a == 0:  # Base case where a is zero
        return b, 0, 1  # Return gcd and coefficients
    g, y, x = egcd(b % a, a)  # Recursive call
    return g, x - (b // a) * y, y  # Return gcd and coefficients


def modinv(a, m):  # Modular inverse
    """Compute modular inverse of a mod m"""  # Docstring
    g, x, _ = egcd(a, m)  # Compute gcd and coefficients
    if g != 1:  # If gcd is not 1, inverse does not exist
        raise Exception("Modular inverse does not exist")  # Raise exception
    return x % m  # Return positive modular inverse


def is_probable_prime(n, k=10):  # Miller-Rabin primality test
    """Miller-Rabin primality test"""  # Docstring
    if n <= 1:  # Handle small n
        return False  # Not prime
    if n <= 3:  # 2 and 3 are prime
        return True  # Prime
    if n % 2 == 0:  # Even numbers greater than 2 not prime
        return False  # Not prime

    # Decompose n-1 = 2^r * d
    r = 0  # Initialize exponent counter
    d = n - 1  # Start from n-1
    while d % 2 == 0:  # Factor out powers of 2
        d //= 2  # Divide by 2
        r += 1  # Increment exponent

    for _ in range(k):  # Repeat test k times
        a = random.randrange(2, n - 2)  # Pick random base
        x = pow(a, d, n)  # Compute a^d mod n
        if x == 1 or x == n - 1:  # If congruent to 1 or -1
            continue  # This round passes
        for _ in range(r - 1):  # Repeat r-1 times
            x = pow(x, 2, n)  # Square x mod n
            if x == n - 1:  # If becomes -1
                break  # Round passes
        else:  # If inner loop did not break
            return False  # Composite
    return True  # Probably prime


def generate_prime(bits=512):  # Generate probable prime
    """Generate probable prime"""  # Docstring
    while True:  # Loop until prime found
        candidate = random.getrandbits(bits)  # Random bits
        candidate |= (1 << bits - 1) | 1  # Ensure odd and top bit set
        if is_probable_prime(candidate):  # Test primality
            return candidate  # Return prime


def generate_rsa_keypair(bits=1024):  # Generate RSA keypair
    """Generate RSA keypair"""  # Docstring
    print("Creating RSA keypair")  # Print creation message
    p = generate_prime(bits // 2)  # Generate prime p
    q = generate_prime(bits // 2)  # Generate prime q
    n = p * q  # Compute modulus n
    phi = (p - 1) * (q - 1)  # Compute phi
    e = 65537  # Public exponent
    d = modinv(e, phi)  # Private exponent
    print("RSA keypair created")  # Print completion
    public_key = (e, n)  # Public key tuple
    private_key = (d, n)  # Private key tuple
    return public_key, private_key  # Return keys


def rsa_encrypt(message_bytes, public_key):  # RSA encryption
    """Encrypt bytes with RSA"""  # Docstring
    e, n = public_key  # Unpack key
    m_int = int.from_bytes(message_bytes, byteorder='big')  # Bytes to int
    if m_int >= n:  # Check size
        raise ValueError("Message too long for RSA modulus")  # Raise error
    c_int = pow(m_int, e, n)  # Modular exponentiation
    c_bytes = c_int.to_bytes((c_int.bit_length() + 7) // 8, byteorder='big')  # Int to bytes
    return c_bytes  # Return ciphertext bytes


def rsa_decrypt(cipher_bytes, private_key):  # RSA decryption
    """Decrypt bytes with RSA"""  # Docstring
    d, n = private_key  # Unpack key
    c_int = int.from_bytes(cipher_bytes, byteorder='big')  # Bytes to int
    m_int = pow(c_int, d, n)  # Modular exponentiation
    m_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, byteorder='big')  # Int to bytes
    return m_bytes  # Return plaintext bytes


def recv_line(sock):  # Receive line from socket
    """Receive a line ending with '\\n'"""  # Docstring
    data = b""  # Initialize buffer
    while True:  # Loop until newline
        chunk = sock.recv(1)  # Receive one byte
        if not chunk:  # If closed
            break  # Break loop
        data += chunk  # Append to buffer
        if chunk == b'\n':  # If newline
            break  # Stop
    return data.decode('utf-8').strip()  # Decode and strip


def send_line(sock, text):  # Send line to socket
    """Send line with '\\n'"""  # Docstring
    sock.sendall((text + "\n").encode('utf-8'))  # Encode and send


# =========================
# CLIENT IMPLEMENTATION
# =========================

HOST = "127.0.0.1"  # Server host address
CONTROL_PORT = 8080  # Control port to connect to
MESSAGE = "Hello"  # Message to send as in spec

def main():  # Main entry for client
    print("Starting client…")  # Print starting message
    client_public, client_private = generate_rsa_keypair()  # Generate client RSA keys

    print("Creating client socket")  # Print message about socket creation
    control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP control socket
    control_sock.connect((HOST, CONTROL_PORT))  # Connect to server control port
    print("Connecting to server")  # Print connection message

    send_line(control_sock, "connect")  # Send connect command
    data_port_str = recv_line(control_sock)  # Receive data port from server
    data_port = int(data_port_str)  # Convert port to integer
    print("Creating data socket")  # Print data socket message

    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create data socket
    data_sock.connect((HOST, data_port))  # Connect to server data port

    print("Requesting tunnel")  # Print tunnel request message
    send_line(control_sock, "tunnel")  # Send tunnel command on control socket

    e_client, n_client = client_public  # Unpack client public key
    client_key_str = f"{e_client},{n_client}"  # Format client public key as string
    send_line(data_sock, client_key_str)  # Send client public key on data socket

    server_key_line = recv_line(data_sock)  # Receive server public key line
    print("Server public key received")  # Print message
    e_server_str, n_server_str = server_key_line.split(",")  # Split server key string
    e_server = int(e_server_str)  # Parse exponent
    n_server = int(n_server_str)  # Parse modulus
    server_public_key = (e_server, n_server)  # Create server public key tuple
    print("Tunnel established")  # Print tunnel established

    print(f"Encrypting message: {MESSAGE}")  # Print message being encrypted
    plaintext_bytes = MESSAGE.encode('utf-8')  # Encode plaintext message
    enc_bytes = rsa_encrypt(plaintext_bytes, server_public_key)  # Encrypt with server public key
    enc_hex = enc_bytes.hex()  # Convert encrypted bytes to hex string

    send_line(control_sock, "post")  # Send post command over control socket
    print(f"Sending encrypted message: {enc_hex}")  # Print encrypted message
    send_line(data_sock, enc_hex)  # Send encrypted hex over data socket

    enc_hash_hex = recv_line(data_sock)  # Receive encrypted hash hex from server
    print("Received hash")  # Print message for received hash
    enc_hash_bytes = bytes.fromhex(enc_hash_hex)  # Convert hex to bytes
    hash_bytes = rsa_decrypt(enc_hash_bytes, client_private)  # Decrypt hash using client private key
    hash_str_from_server = hash_bytes.decode('utf-8')  # Decode hash string
    print("Computing hash")  # Print computing hash message

    sha_local = hashlib.sha256()  # Create local SHA256 object
    sha_local.update(MESSAGE.encode('utf-8'))  # Hash original message
    local_hash_hex = sha_local.hexdigest()  # Get local hash hex

    if hash_str_from_server == local_hash_hex:  # Compare hashes
        print("Secure")  # Print Secure if match
    else:  # If not equal
        print("Compromised")  # Print Compromised

    data_sock.close()  # Close data socket
    control_sock.close()  # Close control socket


if __name__ == "__main__":  # Entry point check
    main()  # Run client main
