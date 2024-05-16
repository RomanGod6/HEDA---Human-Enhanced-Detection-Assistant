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
    hex_str = "1f411f4100c890707b2264617461223a7b227631223a7b22757269223a22687474703a2f2f31302e322e312e39323a383030312f6d732f312e302f227d2c227632223a7b22757269223a22687474703a2f2f31302e322e312e39323a383030312f6170692f76322f227d7d2c2272656d6f7465223a22312e30222c22736964223a22757569643a32353063623133622d653962372d343739312d386131652d373032643730626462333532222c2274746c223a383030302c2274797065223a22616c697665227d0a"
    
    readable_string = hex_to_readable_string(hex_str)
    print(readable_string)
