import pyotp
import sys

if len(sys.argv) < 2:
    print("Usage: python3 get_totp.py <YOUR_2FA_SECRET>")
    sys.exit(1)

secret = sys.argv[1]
try:
    totp = pyotp.TOTP(secret)
    print(f"Your 6-digit code is: {totp.now()}")
except Exception as e:
    print(f"Error generating code: {e}")
