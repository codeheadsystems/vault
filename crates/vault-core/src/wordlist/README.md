# Wordlist

`bip39-english.txt` is the English wordlist of [BIP 39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki),
copied unchanged from `bip-0039/english.txt` in the `bitcoin/bips` repository. BIP 39 is licensed
under the MIT licence (its header reads `License: MIT`). The file has 2,048 unique lower-case words,
one per line, and SHA-256
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.

The passphrase generator in `generate.rs` draws words from it: 11 bits per word.
