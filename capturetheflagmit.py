from pwn import *

# Establish connection to challenge-and-response server
conn = remote('172.232.27.9', 64392)

# Read bit offset (DOV) of data packet
offset = conn.recvn(2)

# Convert the 2-byte offset value to a short
offset_short = u16(offset, endian='little')

# Read 100 bytes of challenge packet
challenge = conn.recvn(100)
print(f'Received {len(challenge)} bytes.')
print(f'Data: {challenge}')

# Find the significant data packet (D) based on the offset value
data_offset = offset_short // 8
data_packet = challenge[data_offset:data_offset + 54]

# Decode the data packet (D) to find the correct option to form the key (K)
option_select = u16(data_packet[0:2], endian='little')
multiple = u32(data_packet[2:6], endian='little')
options = [u32(data_packet[i:i+4], endian='little') for i in range(6, 54, 4)]

print(f'option_select: {option_select}')
print(f'options: {options}')

# Check if option_select is a valid index for the options list
if option_select >= len(options):
    print(f"Error: option_select ({option_select}) is out of range for options list (length {len(options)})")
    exit()

correct_option = options[option_select]
K = multiple * correct_option

# Convert K to a little-endian long (8 bytes)
K_bytes = p64(K, endian='little')

# Send the response K to the server
conn.send(K_bytes)

# Receive the response from the server
response = conn.recvn(16)
print(response)  # Print the response from the server

# Close the connection
conn.close()

# Check if the response is the flag
if b'CTF{' in response:
    # Remove the first character of the flag to make it more challenging for the student to capture
    flag = response[1:]
    print(f'Flag found: {flag.decode("utf-8")}')
else:
    print('Flag not found')

# Learning Experience Addition: Check if option_select is within the range of options
