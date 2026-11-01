import argparse
import base64
import binascii
import logging
import os
import re
import sys
import math
from collections import Counter

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Identifies statistically weak cryptographic keys.")
    parser.add_argument("key_file", help="Path to the file containing the cryptographic key.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("-t", "--threshold", type=float, default=0.95,
                        help="Entropy threshold for weak key detection (default: 0.95). Values closer to 1 indicate higher certainty of weakness.")
    return parser.parse_args()


def calculate_entropy(data):
    """
    Calculates the entropy of the given data.

    Args:
        data (bytes): The data to calculate entropy for.

    Returns:
        float: The entropy of the data.
    """
    if not data:
        return 0.0

    # One Counter pass instead of counting every byte value with a full
    # rescan of the data. The result is bits per byte, so a repeated-byte
    # key scores 0 and uniform random bytes score close to 8.
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def longest_ordered_run(data):
    """
    Length of the longest run of consecutive bytes stepping by +1 or
    by -1 each time (for example 0, 1, 2, 3, ...). Byte frequency
    entropy alone scores the sequence 0 to 255 at a perfect 1.0, so
    order has to be checked separately from frequency.
    """
    if len(data) < 2:
        return len(data)
    best = 1
    current = 1
    step = 0
    for i in range(1, len(data)):
        diff = data[i] - data[i - 1]
        if diff in (1, -1) and (current == 1 or diff == step):
            current += 1
            step = diff
        elif diff in (1, -1):
            current = 2
            step = diff
        else:
            current = 1
            step = 0
        best = max(best, current)
    return best


def find_period(data):
    """
    Smallest period p where the whole input is one block of p bytes
    repeated, or None. A repeated block is predictable however the
    byte frequencies look.
    """
    n = len(data)
    # Every candidate period gets a full scan of the input, so a large
    # key file with no period costs roughly n squared byte comparisons
    # before this gives up. Periods are tried smallest first, which is
    # why a genuinely repeated key is caught quickly and the expensive
    # case is exactly the strong key the caller hopes for.
    for p in range(1, n // 2 + 1):
        if all(data[i] == data[i % p] for i in range(n)):
            return p
    return None


def repeated_block_count(data, block_size=16):
    """Highest repeat count of any single block of block_size bytes."""
    if len(data) < block_size * 3:
        return 0
    blocks = [data[i:i + block_size] for i in range(0, len(data) - block_size + 1, block_size)]
    return max(Counter(blocks).values())


def decode_text_encoding(data):
    """
    If the input is hex or base64 text, return (decoded_bytes, label).
    Scoring the text form caps the score at the text alphabet size, so
    a random key written as hex or base64 scored weak however it was
    generated. Returns (None, None) when the input does not look like
    clean hex or base64 text of at least 16 decoded bytes.
    """
    try:
        text = data.decode("ascii")
    except (UnicodeDecodeError, ValueError):
        return None, None
    compact = "".join(text.split())
    if len(compact) >= 32 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
        return bytes.fromhex(compact), "hex"
    if len(compact) >= 24 and len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        try:
            raw = base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError):
            return None, None
        if len(raw) >= 16 and base64.b64encode(raw).decode("ascii") == compact:
            # Two guards keep ordinary text from being mistaken for an
            # encoded key: the decode must re-encode to the exact same
            # string, and the decoded bytes must be mostly non
            # printable. A sentence that happens to be valid base64
            # decodes to printable text and falls through as raw input.
            printable = sum(1 for b in raw if 32 <= b < 127)
            if printable / len(raw) < 0.85:
                return raw, "base64"
    return None, None


def analyze_key(key_data, entropy_threshold):
    """
    Analyzes the key data for statistical weaknesses.

    Args:
        key_data (bytes): The key data to analyze.
        entropy_threshold (float): The entropy threshold for weak key detection.

    Returns:
        bool: True if the key is considered weak, False otherwise.
    """
    decoded, encoding = decode_text_encoding(key_data)
    if decoded is not None:
        logging.warning(
            f"Input looks {encoding} encoded; scoring the {len(decoded)} decoded bytes, not the text form."
        )
        key_data = decoded

    # Pattern checks run before the entropy score: an ordered sequence
    # or a repeated block is predictable even when its byte frequencies
    # are perfectly even.
    if len(key_data) >= 16:
        period = find_period(key_data)
        if period is not None:
            logging.warning(
                f"Key is statistically weak: the whole input is one {period} byte block repeated."
            )
            return True
        run = longest_ordered_run(key_data)
        if run >= 16:
            logging.warning(
                f"Key is statistically weak: it contains an ordered byte sequence run of {run} bytes."
            )
            return True
        if repeated_block_count(key_data) >= 3:
            logging.warning(
                "Key is statistically weak: the same 16 byte block repeats at least 3 times."
            )
            return True

    try:
        entropy = calculate_entropy(key_data)
        max_entropy = 8  # Maximum entropy for byte data (8 bits)
        normalized_entropy = entropy / max_entropy

        logging.debug(f"Entropy: {entropy}, Normalized Entropy: {normalized_entropy}")

        if normalized_entropy < entropy_threshold:
            logging.warning(f"Key is statistically weak (normalized entropy: {normalized_entropy} < threshold: {entropy_threshold}).")
            return True
        else:
            logging.info(f"Key appears statistically strong (normalized entropy: {normalized_entropy} >= threshold: {entropy_threshold}).")
            return False

    except Exception as e:
        logging.error(f"Error analyzing key: {e}")
        return False


def read_key_from_file(key_file):
    """
    Reads the key data from the specified file.

    Args:
        key_file (str): The path to the key file.

    Returns:
        bytes: The key data, or None if an error occurred.
    """
    try:
        with open(key_file, "rb") as f:  # Open in binary mode
            key_data = f.read()
        return key_data
    except FileNotFoundError:
        logging.error(f"File not found: {key_file}")
        return None
    except IOError as e:
        logging.error(f"Error reading file: {e}")
        return None


def main():
    """
    Main function to execute the weak key detection tool.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    key_file = args.key_file
    entropy_threshold = args.threshold

    if not (0.0 <= entropy_threshold <= 1.0):
        logging.error("Entropy threshold must be between 0.0 and 1.0")
        sys.exit(1)

    key_data = read_key_from_file(key_file)

    # None means the read failed. An empty file read fine: zero bytes
    # carry zero entropy, so it gets the weak verdict instead of a
    # misleading "failed to read" exit.
    if key_data is not None:
        # The verdict is not turned into an exit code: weak and strong
        # both end the run at 0, and the result exists only in the log
        # lines analyze_key writes. A script that needs the answer has
        # to read the output, not the exit status.
        analyze_key(key_data, entropy_threshold)
    else:
        logging.error("Failed to read key data. Exiting.")
        sys.exit(1)


if __name__ == "__main__":
    main()

