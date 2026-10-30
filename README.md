![Banner](banner.png)

# crypto-weak-key-detector
Identifies cryptographic keys that are statistically weak (e.g., due to biased random number generation during key creation) based on entropy analysis. - Focused on Basic cryptographic operations

## Install
`git clone https://github.com/ShadowGuard-AI/crypto-weak-key-detector`

## Usage
`python main.py [-h] [-v] [-t THRESHOLD] key_file`, run from the cloned directory. There is no executable or package by the repo name.

## Parameters
- `-h`: Show help message and exit
- `-v`: Enable verbose logging.
- `-t`: Entropy threshold for weak key detection (default: 0.95).

## Notes

Entropy is computed over the bytes in the file, so a short key caps
the score: a 32 byte sample can reach a normalized entropy of only
about 0.63 even when every byte differs, so the default 0.95
threshold calls every 32 byte key weak. Use a lower threshold (for
example -t 0.5) when judging short keys. An empty file is reported
weak (zero entropy), not as a read failure.
