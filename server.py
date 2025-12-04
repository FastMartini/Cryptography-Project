#!/usr/bin/env python3  # Shebang line to indicate Python 3 interpreter

import socket  # Import socket library for TCP communication
import threading  # Import threading to allow concurrent handling if extended
import hashlib  # Import hashlib for SHA256 hashing
import random  # Import random for prime generation
import sys  # Import sys for potential future use (e.g., exiting)

# =========================
# RSA HELPER FUNCTIONS
# =========================

def egcd(a, b):  # Extended Euclidean Algorithm to compute gcd and coefficients
    """Extended Euclidean Algorithm"""  # Docstring explaining function
    if a == 0:  # Base case when a is zero
        return b, 0, 1  # Return gcd=b and coefficients
    g, y, x = egcd(b % a, a)  # Recursive call with reduced values
    return g, x - (b // a) * y, y  # Return gcd and updated coefficients


def modinv(a, m):  # Modular inverse of a modulo m using extended Euclid
    """Compute modular inverse of a mod m"""  # Docstring
    g, x, _ = egcd(a, m)  # Call extended gcd to get gcd and coefficient
    if g != 1:  # If gcd is not 1, then inverse does not exist
        raise Exception("Modular inverse does not exist")  # Raise exception
    return x % m  # Return positive modular inverse


def is_probable_prime(n, k=10):  # Miller-Rabin primality test
    """Miller-Rabin primality test"""  # Docstring
    if n <= 1:  # Check small n that are not prime
        return False  # Not prime
    if n <= 3:  # 2 and 3 are prime
        return True  # Prime
    if n % 2 == 0:  # Even numbers greater than 2 are not prime
        return False  # Not prime

    # Write n-1 as 2^r * d with d odd
    r = 0  # Initialize r exponent
    d = n - 1  # Start with n-1
    while d % 2 == 0:  # Factor out powers of 2
        d //= 2  # Divide d by 2
        r += 1  # Increase exponent counter

    for _ in range(k):  # Perform k iterations of the test
        a = random.randrange(2, n - 2)  # Choose random base a in [2, n-2]
        x = pow(a, d, n)  # Compute a^d mod n
        if x == 1 or x == n - 1:  # If x is 1 or -1 mod n, continue
            continue  # Test passes this round
        for _ in range(r - 1):  # Repeat r-1 times
            x = pow(x, 2, n)  # Square x mod n
            if x == n - 1:  # If becomes -1 mod n, test passes this round
                break  # Break inner loop
        else:  # If inner loop did not break
            return False  # Composite
    return True  # Probably prime


def generate_prime(bits=512):  # Generate a random probable prime with given bits
    """Generate a probable prime number of given bit size"""  # Docstring
    while True:  # Loop until prime is found
        candidate = random.getrandbits(bits)  # Get random bits
        candidate |= (1 << bits - 1) | 1  # Ensure candidate is odd and has top bit set
        if is_probable_prime(candidate):  # Test primality
            return candidate  # Return prime when found


def generate_rsa_keypair(bits=1024):  # Generate RSA keypair with given key size
    """Generate RSA keypair"""  # Docstring
    print("Creating RSA keypair")  # Print message matching spec
    p = generate_prime(bits // 2)  # Generate first prime p
    q = generate_prime(bits // 2)  # Generate second prime q
    n = p * q  # Compute modulus n
    phi = (p - 1) * (q - 1)  # Compute Euler's totient function
    e = 65537  # Use standard public exponent e
    d = modinv(e, phi)  # Compute private exponent d
    print("RSA keypair created")  # Print success message
    public_key = (e, n)  # Public key tuple
    private_key = (d, n)  # Private key tuple
    return public_key, private_key  # Return both keys


def rsa_encrypt(message_bytes, public_key):  # Encrypt bytes using RSA public key
    """Encrypt bytes with RSA"""  # Docstring
    e, n = public_key  # Unpack public key
    m_int = int.from_bytes(message_bytes, byteorder='big')  # Convert bytes to integer
    if m_int >= n:  # Ensure message integer is smaller than modulus
        raise ValueError("Message too long for RSA modulus")  # Raise error if too large
    c_int = pow(m_int, e, n)  # Perform modular exponentiation for encryption
    c_bytes = c_int.to_bytes((c_int.bit_length() + 7) // 8, byteorder='big')  # Convert back to bytes
    return c_bytes  # Return ciphertext bytes


def rsa_decrypt(cipher_bytes, private_key):  # Decrypt bytes using RSA private key
    """Decrypt bytes with RSA"""  # Docstring
    d, n = private_key  # Unpack private key
    c_int = int.from_bytes(cipher_bytes, byteorder='big')  # Convert ciphertext bytes to integer
    m_int = pow(c_int, d, n)  # Perform modular exponentiation for decryption
    m_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, byteorder='big')  # Convert integer back to bytes
    return m_bytes  # Return plaintext bytes


def recv_line(sock):  # Receive a single line (terminated by newline) from a socket
    """Receive a line (ending with '\\n') from socket"""  # Docstring
    data = b""  # Initialize empty bytes buffer
    while True:  # Loop until newline is found
        chunk = sock.recv(1)  # Receive one byte
        if not chunk:  # If connection closed
            break  # Exit loop
        data += chunk  # Append chunk to buffer
        if chunk == b'\n':  # If newline character received
            break  # Stop reading
    return data.decode('utf-8').strip()  # Decode bytes to string and strip whitespace


def send_line(sock, text):  # Send a line with newline terminator over socket
    """Send text line with '\\n'"""  # Docstring
    sock.sendall((text + "\n").encode('utf-8'))  # Encode text and send with newline


# =========================
# SERVER IMPLEMENTATION
# =========================

HOST = "127.0.0.1"  # Server host address (localhost)
CONTROL_PORT = 8080  # Control port for main commands
DATA_PORT = 8081  # Separate port for data connection as per spec

def handle_client(control_conn, server_public, server_private):  # Handle client commands on control socket
    """Handle one client session"""  # Docstring

    # Create server data socket for data connection
    data_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket for data
    data_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse of address
    data_listener.bind((HOST, DATA_PORT))  # Bind data socket to host and data port
    data_listener.listen(1)  # Listen for one incoming data connection

    client_public_key = None  # Placeholder for client public key
    data_conn = None  # Placeholder for data connection socket

    while True:  # Loop to process commands until connection closes
        command = recv_line(control_conn)  # Read command from control socket
        if not command:  # If no command (client disconnected)
            break  # Exit loop

        if command == "connect":  # Handle connect command
            print("Connection requested. Creating data socket")  # Print message as spec
            send_line(control_conn, str(DATA_PORT))  # Send data port number to client
            data_conn, _ = data_listener.accept()  # Accept incoming data connection from client

        elif command == "tunnel":  # Handle tunnel command
            print("Tunnel requested. Sending public key")  # Print message as spec
            key_line = recv_line(data_conn)  # Receive client public key line from data socket
            parts = key_line.split(",")  # Split key string by comma
            e_client = int(parts[0])  # Parse client exponent
            n_client = int(parts[1])  # Parse client modulus
            client_public_key = (e_client, n_client)  # Store client public key tuple
            e_server, n_server = server_public  # Unpack server public key
            server_key_str = f"{e_server},{n_server}"  # Create string representation of server public key
            send_line(data_conn, server_key_str)  # Send server public key to client

        elif command == "post":  # Handle post command
            print("Post requested.")  # Print message as spec

            enc_line = recv_line(data_conn)  # Receive encrypted message as hex string
            enc_bytes = bytes.fromhex(enc_line)  # Convert hex string back to bytes
            print(f"Received encrypted message: {enc_line}")  # Print encrypted message as hex

            decrypted_bytes = rsa_decrypt(enc_bytes, server_private)  # Decrypt with server private key
            try:  # Try to decode decrypted bytes
                message = decrypted_bytes.decode('utf-8')  # Decode to UTF-8 string
            except UnicodeDecodeError:  # If decoding fails
                message = ""  # Set message as empty to avoid crash
            print(f"Decrypted message: {message}")  # Print decrypted message

            print("Computing hash")  # Print hash computation message
            sha = hashlib.sha256()  # Create SHA256 hash object
            sha.update(message.encode('utf-8'))  # Update hash with message bytes
            hash_hex = sha.hexdigest()  # Get hash as hex string
            print(f"Responding with hash: {hash_hex}")  # Print hash string

            hash_bytes = hash_hex.encode('utf-8')  # Convert hash string to bytes
            if client_public_key is None:  # Ensure tunnel completed
                raise RuntimeError("Client public key not established (tunnel not done)")  # Raise error if no key

            enc_hash_bytes = rsa_encrypt(hash_bytes, client_public_key)  # Encrypt hash with client public key
            enc_hash_hex = enc_hash_bytes.hex()  # Convert encrypted hash bytes to hex string
            send_line(data_conn, enc_hash_hex)  # Send encrypted hash over data socket

        else:  # Handle unknown commands
            # Ignore unknown commands or break
            break  # Break on unexpected command

    if data_conn:  # If data connection exists
        data_conn.close()  # Close data connection socket
    data_listener.close()  # Close data listener socket
    control_conn.close()  # Close control connection socket


def main():  # Main entry point for server
    print("Starting server…")  # Print starting message
    server_public, server_private = generate_rsa_keypair()  # Generate server RSA keys

    print("Creating server socket")  # Print message about creating server socket
    control_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP control listener socket
    control_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow address reuse
    control_listener.bind((HOST, CONTROL_PORT))  # Bind to host and control port
    control_listener.listen(1)  # Listen for incoming control connections
    print("Awaiting connections…")  # Print awaiting connections

    while True:  # Loop forever to accept clients
        control_conn, _ = control_listener.accept()  # Accept an incoming control connection
        # For this assignment, handle a single client sequentially
        handle_client(control_conn, server_public, server_private)  # Handle client session


if __name__ == "__main__":  # Check if script is executed directly
    main()  # Call main function
