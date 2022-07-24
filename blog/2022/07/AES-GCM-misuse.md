- 2022-07-24
- AES-GCM Misuse

This article showcases several, realistic, vulnerabilities associated with AES-GCM. The vulnerabilities are:
- key exchange
- nonce reuse: plaintext recovery
- nonce reuse: hash subkey recovery
- unlimited message size
- unlimited messages

## Key Exchange

A necessary step for unknown peers to securely communicate is to derive a shared secret which cannot be determined by an eavesdropper. Typically, (EC)DHE is used to accomplish this.

```py
from cryptography.hazmat.primitives.asymmetric import x25519

sk = x25519.X25519PrivateKey.generate()
pk = sk.public_key()

# send pk and recieve peer pk in peer_pk

dh_secret = sk.exchange(peer_pk)
```

However, a common mistake is directly using `dh_secret` as an encryption key. Using the shared secret directly is less secure because `dh_secret` is a **random group element** instead of a random bit-string. In other words, there is structure in the value of `dh_secret` because group members have constraints (e.g., the subgroup of even integers will never have LSB set). Consequently, you will reduce the bit security of your encryption key.

To securely derive an encryption key, the shared secret should be passed to a suitable KDF.

```py
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

...
dh_secret = sk.exchange(peer_pk)
# omit a salt or use a salt to "spruce up" randomness 
key = HKDF(hashes.SHA256(), length=32, salt, info=b"encryption key")
```

A caveat here is to make sure [HKDF is parameterized correctly](https://soatok.blog/2021/11/17/understanding-hkdf/) to guarantee KDF security instead of PRF security (which is not suitable here since we do not have a uniformly random bit-string).

An Additional caveat is that vanilla (EC)DHE is insecure because it does not authenticate the parties. Instead, you should use an Authenticated Key Exchange (AKE) to protect against an active attacker.

## Nonce Reuse: Plaintext Recovery

AES-GCM is (in)famously brittle with respect to its nonces. It is _imperative_ that the nonce is never reused with the same key otherwise plaintext recovery and ciphertext forgery is possible.

```py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=128)
cipher = AESGCM(key)

note1 = b"super secret message from Bob to Alice"
note2 = b"\0" * len(note1)

nonce = b"\0" * 12
send(cipher.encrypt(nonce, data=note1, associated_data=None))
send(cipher.encrypt(nonce, data=note2, associated_data=None))
```

A passive attacker will capture the two messages over the wire.

```py
message1 = b"\xb0\xa5(Dy\xd4\x83k\xcf\x1du\xc5pw..."
message2 = b"\xc3\xd0X!\x0b\xf4\xf0\x0e\xaco\x10..."

print(bytes(map(lambda x: x[0] ^ x[1], zip(message1, message2))))
```

Which will output the message! (the trailing data is the authentication tag).

```
b'super secret message?\x82X\xba5\xd4\xcc\xca\xbf...'
```

This is due to how AES-GCM is constructed, which is AES-CTR with GCM slapped on.

![AES-GCM](web/assets/aes-ctr.webp)

The diagram does not include the GHASH components because it is irrelevant here. AES-GCM will create one-time-pad for each plaintext block by appending a 32-bit incrementing counter to the input IV, which is encrypted with AES using the secret key. Then the one-time-pad is xor-d with its associated plaintext block to encrypt it.

The critical flaw with nonce reuse is that the one-time-pads become identical:

```py
ciphertext_a = pad ^ plaintext_a
ciphertext_b = pad ^ plaintext_b

# pad is cancelled out
assert ciphertext_a ^ ciphertext_b == plaintext_a ^ plaintext_b
```

In the attack demonstrated, we used a plaintext padded with 0s to better illustrate the attack. However, in practice it is often possible to manipulate the plaintext to include known values which can leak partial messages.

An important note is this only produces the xor-d plaintexts if the nonces are identical for the blocks, **including the counter**. 

## Nonce Reuse: Hash Subkey Recovery

The previous topic showcased how nonce reuse will leak xor-d plaintexts. However, nonce reuse can allow an attacker to forge "authenticated" ciphertexts.

The GCM part of AES-GCM is Galois Counter Mode which is able to compute a hash over the ciphertext and any associated data. I will not explain how Galois fields work here. The hash is given by GHASH where:

```py
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES

def encrypt(payload: bytes) -> bytes:
    key = b"\x01" * 32
    cryptor = Cipher(AES(key), mode=modes.ECB()).encryptor()
    return cryptor.update(payload) + cryptor.finalize()

def poly_mult(a: int, b: int) -> int:
    # GF(2^128) magic
    z = 0
    for i in range(128):
        z ^= ((b >> i) & 1) * a
        a = (a >> 1) ^ (a & 1) * (0xe1 << 120)
    return z

def intify(string: bytes) -> list[int]:
    f = lambda x: int.from_bytes(x, byteorder="big")
    return [f(string[i:i+16]) for i in range(0, len(string), 16)]

def ghash(subkey: bytes, inputs: bytes) -> int:
    # X^n * Cn + X^n-1 * Cn-1 + ... + X * C1
    x = 0
    for block in intify(inputs):
        x = poly_mult(x ^ block, subkey)
    return x

def gen_auth_tag(nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    # individually pad aad and ciphertext to 16 bytes
    ...

    to_bytes = lambda l, x: x.to_bytes(l, byteorder="big")
    to_int = lambda x: int.from_bytes(x, byteorder="big")

    subkey = to_int(encrypt(b"\0" * 16))
    j0 = nonce + b"\0\0\0\x01"

    aad_len        = to_bytes(8, len(aad))
    ciphertext_len = to_bytes(8, len(ciphertext))
    combined = aad + ciphertext + aad_len + ciphertext_len

    s = ghash(subkey, combined)

    return to_bytes(16, s ^ to_int(encrypt(j0)))

message = b"Moon is hollow?!"
nonce = b"\0" * 12
pad = encrypt(nonce + b"\0\0\0\x02")
ciphertext = bytes(map(lambda x: x[0] ^ x[1], zip(message, pad)))

gen_auth_tag(encrypt(b"\0" * 16), b"...", encrypt(b"secret message"))
```

This will compute a polynomial parameterized by X (the subkey) for some message.

```
g(X) = X^n * Cn + X^n-1 * Cn-1 + ... + X * C1 + J
     = T
```

but if X (i.e., the subkey) is repeated then:

```
g(X) = X^n*Cn + X^n-1*Cn-1 + ... + X*C1 + J
h(X) = X^n*Dn + X^n-1*Dn-1 + ... + X*D1 + J

// addition on GF(2^128) is involutive
g(X) + g(X) = 0 = h(X) + h(X)

// add the polynomials and the authentication tags from two messages
g(X) + h(X) = X^n*(Dn + Cn) + ... + X*(D1 + C1) + g(X) + h(X) = 0
```

In this form, an attacker can solve the equation which produces possible values of the subkey. Once an attacker has derived the subkey, the attacker can forge ciphertexts.

## Unlimited Message Size

If we have 2<sup>32</sup> plaintext blocks then the 32-bit counter will overflow which repeats the nonce for subsequent blocks.

## Unlimited Messages

AES has a block size of 128 bits so all nonces are 128 bits instead of 256-bit for AES-256. Therefore, after encrypting 2<sup>64</sup> messages you have a 50% probability of repeating a nonce. Furthermore, if we have a random nonce then after 2<sup>48</sup> messages we expect a 50% probability of duplication. For real usage, it is necessary to have a cut-off probability (generally 2<sup>-32</sup>).

## Recommendations

Do not write this yourself; use an existing library to handle it all for you.

Otherwise:
- use XChaCha20-Poly1305 (or at least AES-GCM-SIV)
- read [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
