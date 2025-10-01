import binascii
from collections import Counter

# Frequency table for scoring (approximate English letter frequencies)
english_freq = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
    'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
    'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
    'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
    'z': 0.00074, ' ': 0.13000
}

def score_text(text):
    return sum(english_freq.get(chr(byte).lower(), 0) for byte in text)

def single_byte_xor_brute_force(hex_str):
    data = binascii.a2b_hex(hex_str)
    candidates = []

    for key in range(256):
        xored = bytes([b ^ key for b in data])
        try:
            xored.decode('utf-8')  # Check if it's valid UTF-8
            score = score_text(xored)
            candidates.append((score, key, xored))
        except UnicodeDecodeError:
            continue

    # Sort by score descending
    candidates.sort(reverse=True)
    return candidates

# Example input (replace with your own hex string)
cipher_hex = "your_hex_string_here"

results = single_byte_xor_brute_force(cipher_hex)

# Print top 5 results
for score, key, text in results[:5]:
    print(f"Key: {key} | Score: {score:.4f} | Text: {text.decode()}")
