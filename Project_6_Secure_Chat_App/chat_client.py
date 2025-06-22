import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import sys

# --- Key Generation Function ---
def generate_keys():
    """Generates an RSA public and private key pair."""
    key = RSA.generate(2048)
    private_key_pem = key.export_key() # This is bytes (PEM format)
    public_key_pem = key.publickey().export_key() # This is bytes (PEM format)

    # Immediately import the private key PEM into an RSA key object
    private_key_obj = RSA.import_key(private_key_pem)
    
    return private_key_obj, public_key_pem # Return object for private, bytes for public

# --- Key Exchange Function (with length-prefixing) ---
def exchange_keys(sock, my_public_key_pem):
    """
    Exchanges public keys with the other participant over the socket using length-prefixing.
    my_public_key_pem: Your public key in PEM format (bytes).
    Returns the other participant's public key as a PyCryptodome RSA key object.
    """
    # 1. Send my public key with length prefix
    key_len = len(my_public_key_pem)
    sock.sendall(key_len.to_bytes(4, 'big')) # Send 4 bytes indicating key length
    sock.sendall(my_public_key_pem)
    print(f"[DEBUG CLIENT] Sent my public key (length: {key_len} bytes).")

    # 2. Receive other participant's public key with length prefix
    print("[DEBUG CLIENT] Waiting to receive other participant's public key length...")
    received_len_bytes = sock.recv(4) # Receive the 4 bytes indicating key length
    if not received_len_bytes:
        raise Exception("Did not receive key length from other participant.")
    other_key_len = int.from_bytes(received_len_bytes, 'big')
    print(f"[DEBUG CLIENT] Expected other public key length: {other_key_len} bytes.")

    other_public_key_pem = b''
    bytes_received = 0
    while bytes_received < other_key_len:
        # Receive in chunks, ensuring we don't read more than expected key length
        chunk = sock.recv(min(other_key_len - bytes_received, 4096)) 
        if not chunk:
            break # Connection closed unexpectedly
        other_public_key_pem += chunk
        bytes_received += len(chunk)
            
    if bytes_received < other_key_len:
        raise Exception("Did not receive full public key from other participant.")

    print(f"[DEBUG CLIENT] Received other public key (actual length: {len(other_public_key_pem)} bytes).")
    # print(f"[DEBUG CLIENT] Received PEM:\n{other_public_key_pem.decode()}") # Uncomment for detailed debug

    try:
        other_public_key = RSA.import_key(other_public_key_pem)
        print("Other participant's public key imported successfully.")
        return other_public_key
    except Exception as e:
        print(f"[-] [ERROR CLIENT] Failed to import other public key: {e}")
        print(f"[-] [ERROR CLIENT] Received data that caused error:\n{other_public_key_pem}")
        raise # Re-raise the exception for clearer debugging

# --- Encryption and Decryption Functions ---
def encrypt_message(message, public_key_obj):
    """
    Encrypts a message using the recipient's public key object.
    Message must be bytes. Encrypted output is Base64 encoded for safe network transmission.
    """
    # public_key_obj should already be an RSA key object from exchange_keys
    cipher_rsa = PKCS1_OAEP.new(public_key_obj)
    if isinstance(message, str):
        message = message.encode('utf-8')
    try:
        encrypted_message = cipher_rsa.encrypt(message)
        print(f"[DEBUG ENCRYPT] Encrypted message length: {len(encrypted_message)}")
        return base64.b64encode(encrypted_message)
    except ValueError as e:
        print(f"[-] [ERROR ENCRYPT] Encryption failed: {e}. Message might be too long for direct RSA encryption.")
        print("For real-world apps, use hybrid encryption (e.g., AES for data, RSA for AES key).")
        return None

def decrypt_message(encrypted_message_b64, private_key_obj):
    """
    Decrypts a Base64 encoded message using the recipient's private key object.
    """
    # private_key_obj should already be an RSA key object from generate_keys
    cipher_rsa = PKCS1_OAEP.new(private_key_obj)
    try:
        # Debug print for received encrypted message
        print(f"\n[DEBUG DECRYPT] Attempting to decrypt. Received B64 length: {len(encrypted_message_b64)}")
        # print(f"[DEBUG DECRYPT] Received B64 content: {encrypted_message_b64}") # Uncomment for full content if needed

        encrypted_message = base64.b64decode(encrypted_message_b64)
        decrypted_message = cipher_rsa.decrypt(encrypted_message)
        return decrypted_message.decode('utf-8')
    except ValueError as e:
        print(f"[-] [ERROR DECRYPT] Decryption failed (ValueError): {e}")
        # print(f"[-] [ERROR DECRYPT] Data that caused decryption failure: {encrypted_message_b64}") # Uncomment for full content
        return None 
    except Exception as e: # Catch any other unexpected errors during decryption
        print(f"[-] [ERROR DECRYPT] Unexpected error during decryption: {e}")
        return None


# --- Chat Client Logic ---
HOST = '127.0.0.1' # The server's hostname or IP address
PORT = 65432       # The port used by the server

def receive_messages(sock, private_key_obj):
    """Handles receiving and decrypting messages from the other participant."""
    while True:
        try:
            encrypted_msg_b64 = sock.recv(4096)
            if not encrypted_msg_b64:
                print("\nConnection closed by peer.")
                break
            
            # Debug print what was received
            print(f"\n[DEBUG RECEIVE] Raw data received (length: {len(encrypted_msg_b64)} bytes).")
            # print(f"[DEBUG RECEIVE] Raw data content: {encrypted_msg_b64}") # Uncomment if you need to see raw bytes

            decrypted_msg = decrypt_message(encrypted_msg_b64, private_key_obj)
            if decrypted_msg:
                # Clear the current input line to print received message cleanly
                sys.stdout.write('\r' + ' ' * (len("Type your message: ") + 50) + '\r') # Overwrite current line
                sys.stdout.flush()
                print(f"[RECEIVED]: {decrypted_msg}")
                sys.stdout.write("Type your message: ") # Print prompt again
                sys.stdout.flush()
            else:
                # This might happen if non-message data is sent (e.g., during connection setup)
                # Or if decryption truly failed for invalid encrypted data.
                print(f"\n[DEBUG RECEIVE] Received data could not be decrypted.")
                sys.stdout.write("Type your message: ") # Print prompt again
                sys.stdout.flush()
            
        except OSError: # Socket closed, usually happens on exit
            break
        except Exception as e:
            print(f"\nError receiving message in receive_messages: {e}")
            break

def start_client():
    """Initializes and runs the chat client."""
    my_private_key_obj, my_public_key_pem = generate_keys()

    print(f"[DEBUG CLIENT] My private key object type: {type(my_private_key_obj)}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            print(f"Connected to server at {HOST}:{PORT}")
        except ConnectionRefusedError:
            print(f"[-] Error: Connection refused. Make sure the server is running on {HOST}:{PORT}.")
            sys.exit(1) # Exit if server is not running

        # Key Exchange
        other_public_key_obj = exchange_keys(s, my_public_key_pem)
        print("Key exchange complete.")

        # Start receiving messages in a separate thread
        receive_thread = threading.Thread(target=receive_messages, args=(s, my_private_key_obj)) # Pass the key object
        receive_thread.daemon = True
        receive_thread.start()

        print("\n--- Start chatting (type 'exit' to quit) ---")
        sys.stdout.write("Type your message: ") # Initial prompt
        sys.stdout.flush()
        while True:
            message = input("") # Prompt for message to send
            if message.lower() == 'exit':
                break
            
            encrypted_msg = encrypt_message(message, other_public_key_obj)
            if encrypted_msg:
                s.sendall(encrypted_msg)
            sys.stdout.write("Type your message: ") # Prompt after sending
            sys.stdout.flush()
                
    print("\nClient connection closed.")

if __name__ == '__main__':
    print("Starting Secure Chat Client...")
    start_client()