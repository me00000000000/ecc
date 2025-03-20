<h1 align=center>ecc</h1>
<p align=center>X25519 encryption/decryption with Argon2id KDF</p>

```
  -g, --generate: generate a new key pair
  -r, --recipient: specify the recipient public key base64 string
  -k, --private: specify the private key file
  -p, --public: generate a public key from a private key file
  -i, --infile: specify the input file to encrypt or decrypt
  -o, --outfile: specify the output file (applies for encrypt/decrypt/generate)
  -f, --force: overwrite output files
```

## encryption/decryption usage

```
$ ecc -g
Public key: 1htSxV83XGpDfjs9V4EUvHrhpydfjj8Gggi92Pta7i4
Private key saved to 1htSxV83XGp.priv
```

encrypting a file

```
$ cat file | ecc -r 1htSxV83XGpDfjs9V4EUvHrhpydfjj8Gggi92Pta7i4
RVJ7WBHCxTeiI1KXssVM3frNd4aOMk1vYxBljas6ZYuM1N/Q+b80WpC6kSCEU/Vy/2GC2czT412VxHBTAV79RF6O9kjnrTCUK8oOXke0LPIKOB2q
```

to decrypt from STDIN or file:

```
$ echo RVJ7WBHCxTeiI1KXssVM3frNd4aOMk1vYxBljas6ZYuM1N/Q+b80WpC6kSCEU/Vy/2GC2czT412VxHBTAV79RF6O9kjnrTCUK8oOXke0LPIKOB2q | ecc -k 1htSxV83XGp.priv
file contents
```

also --output (-o) and --input (-i) can be used instead of STDIN and STDOUT

```
$ ecc -i file -o encrypted -r 1htSxV83XGpDfjs9V4EUvHrhpydfjj8Gggi92Pta7i4
RVJ7WBHCxTeiI1KXssVM3frNd4aOMk1vYxBljas6ZYuM1N/Q+b80WpC6kSCEU/Vy/2GC2czT412VxHBTAV79RF6O9kjnrTCUK8oOXke0LPIKOB2q
```

```
$ ecc -i encrypted -k 1htSxV83XGp.priv 
file contents
```

## signing usage

sign a message with -s (sign)

```
$ echo 'Important announcement' | ecc -s 1htSxV83XGp.priv
Important announcement

v2LVRoXZh057FXtqy5SikPPoCMYibQZUN1aPtXSgFWAgYeW+y7ZniN23oBs5FaKoeL6/qSA31sRHaTFyB/0kDw
```

verify a signature with -c (check)

```
$ echo 'Important announcement

v2LVRoXZh057FXtqy5SikPPoCMYibQZUN1aPtXSgFWAgYeW+y7ZniN23oBs5FaKoeL6/qSA31sRHaTFyB/0kDw' | ecc -c 1htSxV83XGpDfjs9V4EUvHrhpydfjj8Gggi92Pta7i4
Valid signature
```

<sub>CC BY-SA 4.0</sub>
