def hash_a(data: bytes, initial_seed: int = 7):
    hash_val = 0
    index = 0
    length = len(data)

    while index != length:
        hash_val += data[index]
        hash_val &= 0xFFFFFFFF
        hash_val += (hash_val << initial_seed) & 0xFFFFFFFF
        hash_val &= 0xFFFFFFFF
        hash_val ^= (hash_val >> 6)
        hash_val &= 0xFFFFFFFF
        index += 1

    hash_val += (hash_val << 3) & 0xFFFFFFFF
    hash_val &= 0xFFFFFFFF
    hash_val ^= (hash_val >> 11)
    hash_val &= 0xFFFFFFFF
    hash_val += (hash_val << 15) & 0xFFFFFFFF
    hash_val &= 0xFFFFFFFF

    return hash_val

if __name__ == "__main__":
    input_str = "EnumDisplayMonitors"
    input_bytes = input_str.encode('ascii') 
    result = hash_a(input_bytes)
    print(f"#define {input_str}_HASH 0x{result:08X}")
