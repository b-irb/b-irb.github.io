- 2023-01-22
- Rolling Your Own Crypto

<script src="https://polyfill.io/v3/polyfill.min.js?features=es6"></script>
<script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>

We have all heard "don't roll your own crypto" but what does it mean? Many
developers (including myself) used to think it only extended to primitives
(Curve25519) and ciphers (AES) but the saying extends further. Yet we have to
implement and choose cryptographic protocols for our applications! So what are
the issues with making an uninformed decision?

**Disclaimer: I am not an expert; I am an opinionated person on the Internet.**

A cryptographic protocol can be insecure _regardless of the primitives_. In
cryptography, there is a lot of emphasis on "provable security" where a scheme
is shown to reduce to the security of the underlying primitive. However, a user
developing a custom protocol can introduce vulnerabilities despite using
secure primitives.

This article will explain some of the difficulties involved in writing (and
choosing!) cryptographic protocols. Below are some easy examples of common
issues in custom schemes.

In this example, we use AESGCM to securely transmit a message but there is a
fatal flaw.
```py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=128)
cipher = AESGCM(key)

# client.py
msg = b"send $$ to Bob"
nonce = os.urandom(12)
ct = cipher.encrypt(nonce, data=msg, associated_data=nonce)
send(nonce + ct)

...

# server.py
payload = recv()
nonce, ct = payload[:12], payload[12:]
print(cipher.decrypt(nonce, data=ct, associated_data=nonce))
```

It is trivial for an attacker to reply valid messages for the server to
process (there are [other issues](/blog/2022/07/AES-GCM-misuse) too).
Or what if we simply want to authenticate a user with the following scheme:

1. \\(A\\) sends \\(g^a\\) to \\(B\\)
2. \\(B\\) sends \\(g^b\\) to \\(A\\)
3. \\(A\\) sends \\(\left\langle A, \text{SIG}\_A(g^a)\right\rangle\\) to \\(B\\)
4. \\(B\\) sends \\(\left\langle B, \text{SIG}\_B(g^b)\right\rangle\\) to \\(A\\)

This ties the user identity to the exchanged keys to prevent a user from
intercepting the key exchange. However, an active attacker, C, can reflect the
messages from A to A which will authenticate successfully (called a
[reflection attack](https://en.wikipedia.org/wiki/Reflection_attack)).


## Writing Your Own Protocol

If you are considering writing your own bespoke protocol then you are likely
to encounter the following problems.

### Identities

Most systems (if not all) involve some form of identity which is later
authenticated with another identity or endpoint. User identities are public
keys stored by end-users or an intermediate party (i.e. the service itself).

#### To Be or Not To Be (a CA)

It is _very_ tempting to use standard web [X.509](https://en.wikipedia.org/wiki/X.509)
certificates or adapt them. The adaptations generally mean (ab)using the
existing fields or adding custom extensions to convey application specific
information (e.g. [R3 Corda 4](https://docs.r3.com/en/platform/corda/4.10/community/permissioning.html#certificate-role-extension)).
However, for a certificate to be trusted, it is signed by a Certificate
Authority (CA) **which will reject non-standard certificates.** Consequently,
as the protocol adapts, developers will continue to extend certificates which
requires becoming a CA themselves to sign their custom certs.

The role of a CA is essential to define the trust of a system; anything not
signed by the CA is untrusted. If a CA is compromised or unavailable
(retires) then the entire system becomes vulnerable. Therefore a CA operator
must ensure the utmost security and availability (e.g. [Microsoft Trusted Root Program](https://learn.microsoft.com/en-us/security/trusted-root/program-requirements)), which, frankly
most organisations are not willing or able to do.

Plus, being a CA is a total pain administratively so it is usually best to
offload that work to [someone trustworthy](https://www.ccadb.org/resources).

#### Revocation

If an identity is compromised or a user wants to upgrade to a new scheme then
the existing (published) identity _must be invalidated_. Revocation is easy
in principle but exceedingly hard in practice. There are two main ways to
have built-in revocation:

1. Include an intrinsic expiration
2. Publish a list of all revoked identities (interactive or non-interactive)
3. [Recency challenge responses](https://people.csail.mit.edu/rivest/pubs/Riv98b.pdf)

Web certificates have generally moved to using short-lived certificates which
need frequent renewal as well as publishing a [Certificate Revocation List (CRL)](https://en.wikipedia.org/wiki/Certificate_revocation_list). UEFI SecureBoot uses signed modules which
are checked against [dbx](https://uefi.org/revocationlistfile). The revocation
database is a list of module signatures which are marked as revoked but this
list is monotonically increasing in size because modules are portable. The  UEFI
approach is extremely inflexible because once dbx reaches a certain size, the
on-board flash chips will not be able to store the full revocation list.

Revocation usually rears its ugly head after the initial system design:
If Alice revokes their identity, how does an offline Bob receive that
revocation locally? Is it possible for Eve to kick Bob offline to exploit
a cached identity? How does a user revoke their identity if they have lost
access to their identity? These are crucial questions which are not always
obvious when designers create an initial protocol but quickly become major
roadblocks.

As an aside: revocation also adds more implementation complexity, as evidenced
by the myriad of HTTPS clients that fail to check the certificate properly:
```go
config := &tls.Config{
    VerifyConnection: func(cs tls.ConnectionState) error {
        opts := x509.VerifyOptions{
            DNSName: cs.ServerName,
            Intermediates: x509.NewCertPool(),
        }
        for _, cert := range cs.PeerCertificates[1:] {
            opts.Intermediates.AddCert(cert)
        }
        // Verify does not check revocation!
        _, err := cs.PeerCertificates[0].Verify(opts)
        return err
    },
}
dialer := tls.Dialer{ Config: config };
conn, err := dialer.Dial("tcp", "revoked-ecc-dv.ssl.com:443");
```
This snippet will successfully connect on Linux but will fail on Darwin,
Windows, and iOS ([`Certificate.Verify`](https://pkg.go.dev/crypto/x509#Certificate.Verify)
will perform undocumented rudimentary validity checks on these platforms).
However, the necessity of certificate revocation is somewhat
[controversial](https://www.imperialviolet.org/2014/04/19/revchecking.html).
Despite this, other instances of revocation _are crucial_ to avoid users from
interacting with compromised or impersonated identities.

### Key Distribution

Once a protocol has defined identities then the protocol must distribute those
information using those identities, often to establish a secure channel.
However, key distribution has a host of subtlties regarding privacy and
legality. The key exchange must be authenticated to prevent an active attacker
from intercepting all communication between two parties. For example: if A and
B are proxied by C then C can transparently view all encrypted communication.

1. \\(A\\) sends \\(g^a\\) to \\(C\\)
2. \\(C\\) sends \\(g^c\\) to \\(A\\)
3. \\(C\\) sends \\(g^{c'}\\) to \\(B\\)
4. \\(B\\) sends \\(g^b\\) to \\(C\\)

The key exchange must be authenticated (called an AKE). However, an AKE can
still pose issues affecting privacy. to demonstrate this, a key exchange may
want to protect the identity of a party of the handshake to prevent an active
attacker from retrieving information from a peer.

1. \\(A\\) sends \\(g^a\\) to \\(B\\)
2. \\(B\\) sends \\(\left\langle g^b, B, \text{SIG}\_B(\ldots)\right\rangle\\) to \\(A\\)
3. \\(A\\) sends \\(\left\langle A, \text{SIG}\_A(\ldots)\right\rangle\\) to \\(B\\)

In this scenario, an initiator A attempts to establish a handshake with B. B
reveals its identity to A which could pose a privacy risk in certain
applications (e.g. fingerprint peers on the Internet). However, in certain
scenarios, this could be beneficial to protect the identity of the initiator
(e.g. user is attempting to connect to a _specific_ service). There are other
attacks which can allow users to impersonate other identities or forge
identities.

If the key exchange uses static keys or keys fully determined by participant
identities then an attacker can compromise this key to decrypt all future and
prior communications. A method to add forward secrecy is to derive ephemeral
keys for each session (e.g., FFDHE, ECDHE provide this). However, you guessed
it, this can also be compromised if the key derivation process is not
sufficiently random (e.g. failing to parameterise the base element in DHE,
like [IKE](https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf)).

### State Management

State management is a crucial part of an interactive process. A scheme which
is secure under the presence of an eavesdropper may not be secure under
multiple messages (e.g. encrypting blocks with the same AES key). Similarly,
a more complex scheme may consist of a variety of handshakes and messages
which, if out of order, can disrupt the state. State management can pertain
to the session itself or individual messages within a session. The session
state itself may include: nonces, protocol state (i.e. what messages have been
previously received and what is expected), involved identities, etc. The
message state may include: authentication data, conditional extensions, and
message features.

Session state can be exploited by replaying messages, sending messages out of
order, racing messages, responding with unexpected messages, or terminating
a protocol exchange early.

```py
# expected state transition
state_transition = {
    'send_ga': 'recv_gb',
    'recv_gb': 'send_auth_ga',
    'send_auth_ga': 'recv_auth_gb',
    'recv_auth_gb': 'done',
    # heartbeat message can be sent after auth to keep connection alive
    'heartbeat': 'done',
}

state = 'send_ga'
while sate != 'done':
    # send relevant message for current state
    send_msg(state)
    # receive expected protocol response then transition
    response = recv_msg(...)
    state = state_transition[response.action]
```

If a peer responded with a heartbeat message instead of authenticating itself
then the protocol implementation will skip over the authentication, allowing
for "secure and authenticated" communication with the unauthenticated party.

Message state can be exploited by removing or adding optional fields of a
message. A practical example is an authenticated message with authenticated
optional extensionss.

```py
# Message Format
# u8    variant
# u8    number of extensions
# ...   <extension data>
# u256  message authentication code
# ...   payload

# Extension Format
# u8    variant
# u256  message authentication code
# ...   payload

msg = recv_message(...)
# authenticate message payload and variant
computed_mac = hmac(shared_key, msg.variant + msg.payload)
assert(computed_mac == msg.hmac)

for i in range(msg.n_extensions):
    extension = msg.extensions[i]
    # authenticate extension payload and variant
    computed_mac = hmac(shared_key, extension.variant + extension.payload)
    assert(computed_mac == extension.hmac)
    process_extension(extension)

process_message(msg)
```

This message format is incredibly fragile because an attacker can modify the
optional extensions because the field containing the number of extensions is
not authenticated. Furhtermore, regardless of authenticating the number of
extensions, an attacker can substitute or shuffle authenticated extensions
because the extensions are authenticated independently. This is not a contrived
example, this scenario was able to exploit [NFC messages](https://ieeexplore.ieee.org/document/6148458).

## Opportunity Costs

The cost of implementing a le epic modern protocol can quickly exceed the
benefit of using an existing protocol so keep this in mind! It is tempting
to pick the exciting option of designing a new protocol but practicality
should be weighed heavily. Keep it simple, stupid!

## Choosing A Protocol

"Okay! If I can't write my own protocol, what do I do?!". The
solution is to choose from an available protocol with proper security
considerations, tests, and proofs. An additional bonus is that using an
existing protocol allows you to use standardisation/whitepaper documents as
design documentation _and you can use existing implementations_. If you cannot
choose from an existing protocol then there are steps to securely adapt or
construct a protocol.

_When in doubt, choose the boring stuff like TLSv1.3 or SSHv2._

### Understand Your Needs

In order to choose a suitable protocol, you need to understand what specific
properties you need from a protocol:

- Authentication without PSKs
- Authentication using PSKs
- Quantum secure key exchange and encryption.
- Multi-party key exchange and revocation.
- Multi-party distribution (e.g. [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing))
- Blind processing (e.g., [homomorphic encryption](https://en.wikipedia.org/wiki/Homomorphic_encryption), [Zero Knowledge Proofs](https://en.wikipedia.org/wiki/Zero-knowledge_proof), [blinding](https://en.wikipedia.org/wiki/Blinding_\(cryptography\)), [garbled circuits](https://en.wikipedia.org/wiki/Garbled_circuit)).

If an existing protocol implementation does not provide all the desired
features then a protocol design can be adapted or implemented yourself (e.g.,
[X3DH](https://www.signal.org/docs/specifications/x3dh/#the-x3dh-protocol),
[OPAQUE](https://blog.cloudflare.com/opaque-oblivious-passwords/),
[SIGMA-R](/blog/2022/07/SIGMA-R.html))
It is possible to develop a secure protocol design from scratch using the
[Noise Protocol Framework](http://noiseprotocol.org/noise.html) and the
[NoiseSocket Protocol](https://noisesocket.org/spec/noisesocket/). The Noise
suite is a method of securely generating protocols with a set of desired
properties (e.g. creates an AKE between two parties, protecting the responder's
identity). All protocols constructed using Noise are guaranteed to be secure!
The [Noise Explorer](https://noiseexplorer.com/) tool can generate formal
verification models for a created protocol which assures its security
properties.

To show the ease of Noise, let's create a protocol live! We want:
- Forward secrecy beween two unknown parties
- Mututal authentication with static public keys
- Efficient and secure symmetric encryption with a shared key
- Protect the identity of the responder

```
-> e
<- e, ee
-> s, se
<- s, es
...
```

The following pattern will derive a shared key via DH then derive a new shared
key using the public keys (identities) of the peers. A passive attacker is
unable to snoop on the identity of the initiator and an active attacker is
unable to retrieve the identity of the responder because it must authenticate
itself first. However, an attacker can forge an authentication message if they
are able to complete a handshake with another identity. The forgery will not
allow the attacker to encrypt messages but could be used to implicate a user
for interacting with another user. This example demonstrates the ease of use
of Noise protocols and some of the footguns if you use Noise without thinking!

If no existing solution exists and the protocols produced by Noise are not
scratching that _business logic itch_ then you will have to commit the
ultimate sin of DIY (or argue with your manager about how this feature is
impractical and a future liability). When designing a protocol, you should
make _heavy use_ of existing solutions to elements of your problem set then
have formal audits into the security guarantees of the protocol. Formal
verification models can create guarantees **on the design of the protocol**
but the implementation itself will need additional auditing (regular fuzzing,
manual-review, divergent fuzzing, etc).

### Understand Your Choice

Even a secure and widely used protocol can have dangerous behaviours. It is
imperative that you fully investigate all behavoiurs and "idiosyncracies" of
the chosen protocol. For example: TLSv1.3 has a 0-RTT mode where a client
can initiate a TLS handshake while providing information encrypted with the
secret key of a previous session. The resumption _is not fully authenticated_
because an attacker can replay the packet **so the action must be idempotent.**

```rs
// Attempt to connect to hostname with reasonable parameters.
let remote_addr = "google.com:443";
let server: ServerName = "google.com".try_into().expect("bad hostname");
let config = {
    let mut cfg = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(certs)
        .with_no_client_auth();
    cfg.enable_early_data = true;
    Arc::new(cfg)
};

// Create TLS connection to cache Early Data PSK.
let mut conn = std::net::TcpStream::connect(remote_addr).unwrap();
let mut prev = ClientConnection::new(Arc::clone(&config), server.clone())?;
let mut stream = Stream::new(&mut prev, &mut conn);
stream.write(b"GET / HTTP/1.0\r\n\r\n").unwrap();
let mut buf = Vec::new();
stream.read(&mut buf).unwrap();
core::mem::drop(prev);
core::mem::drop(conn);

// Create a second connection which can use the PSK.
let mut conn = std::net::TcpStream::connect(remote_addr).unwrap();
let mut client = ClientConnection::new(Arc::clone(&config), server)?;
// Attempt to send 0-RTT payload.
if let Some(mut writer) = client.early_data() {
    writer.write(b"GET / HTTP/1.0\r\nEarly-Data: 1\r\n\r\n").unwrap();
} else {
    panic!("Server does not accept early data.")
}
// Retrieve response from server.
let mut stream = Stream::new(&mut client, &mut conn);
let mut _buf = vec![0; 100]; // read_to_end closes connection?
stream.read(&mut buf).unwrap();
```

This example is safe because `GET /` is _generally_ idempotent but if we had
a RESTful API or the early data was an action then the early data payload could
be replayed or delivered out-of-order. If you are interested, [this post](https://blog.trailofbits.com/2019/03/25/what-application-developers-need-to-know-about-tls-early-data-0rtt/)
goes into more detail about 0-RTT footguns. To mitigate this, some applications
will include an "Early Data cookie", similar to a CSRF token where the request
must have a matching value. Alternatively, Early Data can be disabled outright.

Other choices can have [devastating consequences](https://soatok.blog/2020/11/27/the-subtle-hazards-of-real-world-cryptography/). For example: "encryptment" is a property
where encryption authenticates the ciphertext and the key it was encrypted
with. A scheme lacking encryptment (AESGCM, ChaCha20Poly1305) is vulnerable to
Multi-Key Collision Resistance (MKCR) attacks. MKCR is most famously
demonstrated in Facebook as [Invisible Salamanders](https://eprint.iacr.org/2019/016)
but has also cropped up in [Threema](https://breakingthe3ma.app/). In summary,
MKCR allows multiple authenticated ciphertexts to successfully decrypted under
multiple keys. This allows users to send messages which decrypt to different
users or brute-force multiple keys simultaneously against a decryption oracle.

Other protocols may have [canonicalization attacks](https://soatok.blog/2021/07/30/canonicalization-attacks-against-macs-and-signatures/) and other subtlties which can break
your applications. You should read _all usage guidance_ on your chosen
protocol, this includes RFCs, NIST guidance, and occasionally research papers.

The protocol choice should have room for flexibility, _regardless of current
plans_ because you will likely need to change to a new ciphersuite for
compliance reasons or in response to a vulnerability disclosure. Flexibility
is a subtle art but has been explained pretty [thoroughly](https://soatok.blog/2022/08/20/cryptographic-agility-and-superior-alternatives/) (or furr-ily, hah!).

## Closing Thoughts

If you choose to implement or adapt a protocol then you should have opinions
from cryptographers and other developers to ensure the protocol is both secure
and usable. Provable security takes many forms, one is a framework like
[ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) formally verifies
the secrecy and authentication of the protocol. You should also be aware of
existing research into breaking popular protocols (I see a _lot_ of interactive
protocols with plaintext compression which can leak plaintext).

And whatever you do, for God's sake, don't _ever_ roll your own primitives.

