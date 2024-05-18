def hex_to_readable_string(hex_str):
    try:
        # Convert hex string to bytes
        bytes_object = bytes.fromhex(hex_str)

        # Attempt to decode using various encodings
        encodings = ['utf-8', 'latin1', 'ascii']
        for encoding in encodings:
            try:
                readable_string = bytes_object.decode(encoding)
                return readable_string
            except UnicodeDecodeError:
                continue

        # Fallback: Show hexadecimal representation for non-printable characters
        hex_fallback = ' '.join(f'{b:02x}' for b in bytes_object)
        return f"Hex fallback: {hex_fallback}"
    except Exception as e:
        return f"Error converting hex to string: {e}"

# Example usage
if __name__ == "__main__":
    hex_str = "b123076c008514464d2d534541524348202a20485454502f312e310d0a484f53543a203233392e3235352e3235352e3235303a313930300d0a4d414e3a2022737364703a646973636f766572220d0a4d583a20310d0a53543a2075726e3a6469616c2d6d756c746973637265656e2d6f72673a736572766963653a6469616c3a310d0a0d0a"
    
    readable_string = hex_to_readable_string(hex_str)
    print(readable_string)
