import argparse
import logging
import os
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


def analyze_key(key_data, entropy_threshold):
    """
    Analyzes the key data for statistical weaknesses.

    Args:
        key_data (bytes): The key data to analyze.
        entropy_threshold (float): The entropy threshold for weak key detection.

    Returns:
        bool: True if the key is considered weak, False otherwise.
    """
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
        analyze_key(key_data, entropy_threshold)
    else:
        logging.error("Failed to read key data. Exiting.")
        sys.exit(1)


if __name__ == "__main__":
    main()

