![Introduction banner: the moon garden before any name is spoken](intro-banner.png)

# crypto-weak-key-detector

Title block: the name above is set in Bona Nova in moon white on a night garden plate, with a silver rule beneath it and one small moonflower at the left of the first heading only, in the manner of a watch log cover.

![Logo](logo.png)

![Banner](banner.png)

![Animated scene](scene.svg)

![Major separator](sep-heavy.svg)

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

![Major separator](sep-heavy.svg)

> Watch note: patterns come before scores. An ordered run of 16 or more bytes, one block repeated end to end, or a 16 byte block repeating at least 3 times is reported weak whatever the entropy score would have been.

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

![Major separator](sep-heavy.svg)

## Watch notes, gathered in the garden

The buttons of this re-skin read Check the Key File, Show the Full Count, and Show the Watch Notes. Its headings read Patterns Before Scores, The Verdict Lives in the Log, Short Keys Cap Their Own Score, Judged on the Bytes, Not the Wrapping, and Only Real Failures Exit 1. The live README carries no licence line and no install identity fault: its install line names ShadowGuard-AI correctly, with hyphen and no .git ending. The repository LICENSE file carries the MIT License. Its holder line gives a pen name together with a single initial for the remaining name. That fact is recorded. The initial is not expanded.
