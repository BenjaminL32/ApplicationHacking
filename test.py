import sys
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

def score_text(text_bytes):
    """Score bytes using english_freq. Non-ascii bytes score 0."""
    s = 0.0
    for b in text_bytes:
        c = chr(b).lower()
        s += english_freq.get(c, 0)
    return s

def single_byte_xor_brute_force_bytes(data_bytes):
    """Return list of (score, key, decrypted_bytes) for all 256 keys (sorted desc)."""
    candidates = []
    for key in range(256):
        xored = bytes([b ^ key for b in data_bytes])
        # Try to ensure it is likely a textual candidate: allow decode if possible
        # We'll still score binary-like results but prefer decodable text.
        try:
            xored.decode('utf-8')  # valid UTF-8 check
        except UnicodeDecodeError:
            # still compute score (non-decodable -> likely poor score), but mark low priority
            score = score_text(xored)
            candidates.append((score, key, xored))
            continue
        score = score_text(xored)
        candidates.append((score, key, xored))
    candidates.sort(reverse=True, key=lambda t: t[0])
    return candidates

def analyze_file(filename, top_n_per_line=3):
    best_overall = None  # tuple (score, key, bytes, line_no, raw_hex)
    with open(filename, 'r') as f:
        for line_no, raw in enumerate(f, start=1):
            hex_str = raw.strip()
            if not hex_str:
                continue
            # clean possible spaces in hex string
            hex_str_clean = ''.join(hex_str.split())
            # skip lines that aren't valid hex or not length 60 (optional)
            try:
                data = binascii.unhexlify(hex_str_clean)
            except (binascii.Error, ValueError):
                print(f"Line {line_no}: skipping invalid hex -> {hex_str!r}")
                continue

            candidates = single_byte_xor_brute_force_bytes(data)
            # report top N candidates for this line
            print(f"\nLine {line_no} (hex len={len(hex_str_clean)}): top {top_n_per_line} candidates:")
            for i, (score, key, dec_bytes) in enumerate(candidates[:top_n_per_line], start=1):
                # decode for printing safely; replace undecodable bytes
                dec_text = dec_bytes.decode('utf-8', errors='replace')
                print(f"  {i}. Score: {score:.5f} | Key: {key} (0x{key:02x}) | Text: {dec_text}")

            # update overall best
            top_score, top_key, top_dec = candidates[0]
            if (best_overall is None) or (top_score > best_overall[0]):
                best_overall = (top_score, top_key, top_dec, line_no, hex_str_clean)

    # final summary
    if best_overall:
        bscore, bkey, bdec, blineno, bhex = best_overall
        print("\n" + "="*60)
        print("Best overall candidate:")
        print(f" Line: {blineno}")
        print(f" Hex (line): {bhex}")
        print(f" Key: {bkey} (0x{bkey:02x})")
        print(f" Score: {bscore:.5f}")
        print(" Decrypted text:")
        print(bdec.decode('utf-8', errors='replace'))
        print("="*60)
    else:
        print("No valid candidates found.")

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        filename = sys.argv[1]
    else:
        # default filename; change if you like
        filename = "hex_strings.txt"

    analyze_file(filename, top_n_per_line=3)
