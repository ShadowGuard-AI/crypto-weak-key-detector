![Banner](banner.png)

# crypto-weak-key-detector
Identifies cryptographic keys that are statistically weak (e.g., due to biased random number generation during key creation) based on entropy analysis, plus ordered sequence and repeated block pattern checks, with hex and base64 text input decoded before scoring. - Focused on Basic cryptographic operations

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

Byte frequency is not the whole check. Before the entropy score,
the tool looks for patterns that frequency counts miss: an ordered
byte sequence run of 16 or more bytes (the sequence 0 to 255, for
example), an input that is one block of bytes repeated end to end,
and a 16 byte block that repeats at least 3 times. Any of those is
reported weak whatever the entropy score would have been.

Text encoded input is decoded before scoring, because a text
alphabet caps the entropy score however the key was generated. If
the file holds hex text (at least 32 hex characters) or base64 text
that decodes cleanly to at least 16 bytes, the tool logs a warning
that the input looks encoded and scores the decoded bytes instead,
pattern checks included. A random key written as hex or base64 is
therefore judged on the key bytes, not on the encoding.
