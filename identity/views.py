from django.shortcuts import render
import hashlib
import hmac
import binascii

# Create your views here.
def index(request):
    return render(request,'identity/index.html')

def encode(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')

        # Concatenate user data into a string
        user_data = f"{first_name}{last_name}{email}"

        # Generate SHA-256 hash of user data
        sha256_hash = hashlib.sha256(user_data.encode()).digest()

        # Generate private key from the hash
        private_key = hmac.new(key=b'secret_key', msg=sha256_hash, digestmod=hashlib.sha256).digest()

        # Encode the private key in hexadecimal format for better readability
        private_key_hex = binascii.hexlify(private_key).decode()

        # Return the SHA-256 hash as the encrypted data
        encrypted_data = sha256_hash.hex()

        # Store the encrypted data and private key in the session for later retrieval
        request.session['encrypted_data'] = encrypted_data
        request.session['private_key'] = private_key_hex

        return render(request, "identity/encode.html", {'encrypted': encrypted_data, 'private': private_key_hex})

    return render(request, "identity/encode.html")

def decode(request):
    if request.method == 'POST':
        encrypted_data_hex = request.POST.get('encrypted_data')
        private_key_hex = request.POST.get('private_key')

        # Decrypt the encrypted data from hexadecimal format
        unhexlified_data = bytes.fromhex(encrypted_data_hex)

        # Generate private key from the unhexlified_data
        pk2 = hmac.new(key=b'secret_key', msg=unhexlified_data, digestmod=hashlib.sha256).digest()

        # Encode the private key in hexadecimal format
        pk2_hex = binascii.hexlify(pk2).decode()

        if pk2_hex == private_key_hex:
            # Hash verification succeeded
            verified = True
            return render(request, "identity/decode.html", {'verified': verified})
        else:
            # Hash verification failed
            unverified = True
            return render(request, "identity/decode.html", {"unverified":unverified})

    return render(request, "identity/decode.html")
