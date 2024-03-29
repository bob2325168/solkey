# solkey
Generate Solana keys using mnemonics

## disclaimer
> The use of this tool does not guarantee security or usability for any
> particular purpose. Please review the code and use at your own risk.

## installation
This step assumes you have [Go compiler toolchain](https://go.dev/dl/)
installed on your system.

Download this repo to a folder and cd to it.
```bash
go install
```
Add autocompletion for `bash` to your `.bashrc`
```bash
source <(solkey completion bash)
```

## generate keys
Solana keys can be generated using mnemonic. [bip39](https://github.com/kubetrail/bip39)
can be used for generating new mnemonics:
```bash
bip39 gen
patient board palm abandon right sort find blood grace sweet vote load action bag trash calm burden glow phrase shoot frog vacant elegant tourist
```

```bash
solkey gen
Enter mnemonic: patient board palm abandon right sort find blood grace sweet vote load action bag trash calm burden glow phrase shoot frog vacant elegant tourist
pub: AYFf2pT5o1FqzwQmPM6pfW7sPdK4oVxwD7cHrt3X4jY8
prv: 2WKuYzXcJk53A1ymJ2mH182TuqBfSnMShyoA4ma1b9cUxXi5fo1bm3Va4eTxRuafmpYwH2kNM1ioHdG8fYy1zSH2
```

The default chain derivation path is `m/44'/501'/0'/0'`, were `501'` stands for
hardened Solana chain address and `44'` stands for hardened purpose, implying
`BIP-44` spec.

> Solana keys are `ed25519` keys and therefore only support hardened
> path derivation.

The keys are expected to match those generated by [Phantom Solana Wallet](https://phantom.app/).
The default key will correspond to a derivation path of `m/44'/501'/0'/0'` and the key
for the next account will correspond to a derivation path of `m/44'/501'/1'/0'` and so on.

The chain derivation path can be changed
```bash
solkey gen --derivation-path="m/44'/501'/1'/0'"
Enter mnemonic: patient board palm abandon right sort find blood grace sweet vote load action bag trash calm burden glow phrase shoot frog vacant elegant tourist
pub: 4kVGwzQweEDciB7PxiYc2tg3EeGCBZNgighjcTtP4mao
prv: 52JyCw73NWYKfkEUfZpUQKTvqVGyFD7tcMZCk49559jpRnCUJxcutmYCJcXkdqb5jpH7AFRBgCXn8U29R1BuhoBM
```

Keys can be additionally protected using a passphrase:
```bash
solkey gen --use-passphrase 
Enter mnemonic: patient board palm abandon right sort find blood grace sweet vote load action bag trash calm burden glow phrase shoot frog vacant elegant tourist
Enter secret passphrase: 
Enter secret passphrase again: 
pub: 6WMmLngr75jtYWSqa8CCtByEvxYL6gLKHDA2PfxbZKZ7
prv: 3uZ4zXvxUP2zGjb5o4rQA4fEhsgZF9jSJN1faf3YguMcM4Rv1opVjCkTeUe4kVjhrFXxzZRUXu1QsaHXeHbUASsX
```

Mnemonic is validated and expected to comply to `BIP-39` standard, however, an 
arbitrary mnemonic can be used by switching off validation

```bash
solkey gen --skip-mnemonic-validation 
Enter mnemonic: this is an invalid mnemonic
pub: Bxyv8GmMbC9gxTpD3WExMJdPXNzPNL8uXf5eLzg24b8T
prv: 4egc6wLHqkUWKGssbQ9RMLPYvCFor4Si3mWG7BP3GQck5VQ7hzspBPewbZVWLc7JG5v3eioT5iTSQtp3926q5JpP
```

## validate keys
Key validation checks for key string format, length and other characteristics.
For instance, if a private key is entered, it also checks if a public key
can be derived from it.

```bash
solkey gen
Enter mnemonic: patient board palm abandon right sort find blood grace sweet vote load action bag trash calm burden glow phrase shoot frog vacant elegant tourist
pub: AYFf2pT5o1FqzwQmPM6pfW7sPdK4oVxwD7cHrt3X4jY8
prv: 2WKuYzXcJk53A1ymJ2mH182TuqBfSnMShyoA4ma1b9cUxXi5fo1bm3Va4eTxRuafmpYwH2kNM1ioHdG8fYy1zSH2
```

These keys can be validated:
```bash
solkey validate 
Enter prv or pub key: AYFf2pT5o1FqzwQmPM6pfW7sPdK4oVxwD7cHrt3X4jY8
public key is valid
```

```bash
solkey validate 
Enter prv or pub key: 2WKuYzXcJk53A1ymJ2mH182TuqBfSnMShyoA4ma1b9cUxXi5fo1bm3Va4eTxRuafmpYwH2kNM1ioHdG8fYy1zSH2
private key is valid
```

## sign input
Sign arbitrary data using private key. Signing allows someone to verify the signature using 
public key
```bash
solkey sign this arbitrary input
Enter prv key: 2WKuYzXcJk53A1ymJ2mH182TuqBfSnMShyoA4ma1b9cUxXi5fo1bm3Va4eTxRuafmpYwH2kNM1ioHdG8fYy1zSH2
hash:  9PW5sgZmMnaBYgJxUQASyDQoeKoxPcgBLvCJEHVEFqb5
sign:  4yAcM3NoXp4va75L8dYrbwE1XhXXo3GCXiP5KwF5HuoRrTzFYbfFeNrtdzFuYtix3vcGEH8engirSXPL66BCRnKj
```

## verify signature
```bash
solkey verify 
Enter pub key: AYFf2pT5o1FqzwQmPM6pfW7sPdK4oVxwD7cHrt3X4jY8
Enter hash: 9PW5sgZmMnaBYgJxUQASyDQoeKoxPcgBLvCJEHVEFqb5
Enter sign: 4yAcM3NoXp4va75L8dYrbwE1XhXXo3GCXiP5KwF5HuoRrTzFYbfFeNrtdzFuYtix3vcGEH8engirSXPL66BCRnKj
signature is valid for given hash and public key
```

## generate hash
Hash can be generated for an input
```bash
solkey hash this arbitrary input
hash:  9PW5sgZmMnaBYgJxUQASyDQoeKoxPcgBLvCJEHVEFqb5
```
