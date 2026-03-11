import subprocess
import json
import struct
import sys

# Prepare the payload
payload = json.dumps({"action": "ping"}).encode('utf-8')
message = struct.pack('<I', len(payload)) + payload

print("Calling wrapper...")
try:
    process = subprocess.Popen(
        ['/Users/yooju/Desktop/s2n/native_host_wrapper.sh'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate(input=message, timeout=2)
    print("Return code:", process.returncode)
    print("STDOUT:", stdout)
    print("STDERR:", stderr.decode('utf-8'))
except Exception as e:
    print("Failed exactly like Chrome:", e)
