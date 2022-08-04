- 2022-07-25
- SIGMA-R

<script src="https://polyfill.io/v3/polyfill.min.js?features=es6"></script>
<script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>

SIGMA-R is a member of the [SIGMA (SIGn-and-MAc)](https://webee.technion.ac.il/~hugo/sigma-pdf.pdf)
authenticated key exchange family, using Diffie-Hellman. The SIGMA family was
used with IPSec IKE(straightforv2) and inspired early versions of TLS. This article explains the SIGMA protocol family with heavy references to the [SIGMA presentation](https://webee.technion.ac.il/~hugo/sigma.html).

It is not to be confused with [sigma protocols](https://crypto.stanford.edu/cs355/19sp/lec6.pdf).


## Primer: Diffie-Hellman

Two parties, \\(A\\) and \\(B\\), have a shared generator \\(g \in G\\) where \\(G\\) is a group and \\(\forall a,b \in \mathbb{N}.\\,\\, g^{ab} = g^{ba}\\). For FFDHE, it is important to parameterize the group and generator ([which many IKE servers failed to do](https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf)). 

The below command will generate custom FFDHE parameters:

```sh
$ openssl dhparam -out dhparam 4096
```

ECDHE does not require parameterization because ECDHE uses safe curves (e.g., [Curve25519](https://cr.yp.to/ecdh/curve25519-20060209.pdf) or [others](https://safecurves.cr.yp.to/)).

$$
\begin{eqnarray*}
\text{A} &\xrightarrow{g^a} \text{B} \\\\
\text{A} &\xleftarrow{g^b} \text{B} 
\end{eqnarray*}
$$

Now A and B can compute \\(g^{ab} = x = g^{ba}\\) then derive a shared key, \\(\text{key} = \text{KDF}(x)\\).

## Authenticated Diffie-Hellman

The problem with Diffie-Hellman is that the parties are unauthenticated so it is feasible for an active attacker \\(E\\) to intercept all communication.

$$
\begin{eqnarray*}
\text{A} \xrightarrow{g^a} \text{E} \xrightarrow{h^c} \text{B} \\\\
\text{A} \xleftarrow{h^d} \text{E} \xleftarrow{g^b} \text{B}
\end{eqnarray*}
$$

However, blindly attaching signatures introduces an identity midbinding attack and other vulnerabilities.

$$
\begin{eqnarray*}
\text{A} \xrightarrow{g^a} &\text{E} \xrightarrow{g^a} \text{B} \\\\
\text{A} \xleftarrow{g^b,\\,B,\\,\text{SIG}\_\text{B}(g^b, g^a)} &\text{E} \xleftarrow{g^b,\\,B,\\,\text{SIG}\_\text{B}(g^b,\\,g^a)} \text{B} \\\\
\text{A} \xrightarrow{A,\\,\text{SIG}\_\text{A}(g^a, g^b)} &\text{E} \xrightarrow{E,\\,\text{SIG}\_\text{E}(g^a,\\,g^b)} \text{B}
\end{eqnarray*}
$$

\\(B\\) believes they're talking to \\(E\\) whereas \\(A\\) believes they're talking to \\(B\\). Additionally, this leaks the identity of both \\(A\\) and \\(B\\) which restricts privacy. There are other schemes for attempting to implement authentication by attaching a signature to all handshake messages but this is vulnerable to a reflection attack.

## Improvements

We need to authenticate both parties without leaking their identities, prevent identity misbinding, and prevent reflection attacks -- with as few round-trips as possible.

SIGMA-R compromises on the privacy of the initiator (the SIGMA-I variant protects the identity of the initiator). 

## STS

An early design of an authenticated key exchange was STS. However, STS suffered from identity misbinding where an attacker could register their identity (assuming proof of posession of the private key is not required) then replace the initiating identity with their own. 

An additional variant of STS (MACed-signature) also suffered from identity misbinding.

From the [paper presenting SIGMA](https://webee.technion.ac.il/~hugo/sigma-pdf.pdf):

> The failure to the misbinding attack is more essentially related to the
> _insufficiency_ of binding the Diffie-Hellman key with signatures. Such a binding [...]
> provides a proof that _someone_ knows the session key, but does not prove
> _who_ this _someone_ is.

### Photuris

Photuris improved over the MACed-signature variant by binding the DH key under the signature, alongside the peers' parameters.

$$ \text{SIG}\_\text{X}(g^a,g^b,\text{PRF}(g^{ab})) $$

The \\(\text{PRF}\\) (e.g., [MD5](https://datatracker.ietf.org/doc/html/rfc2522#section-10) -- the protocol is from 1999) is used to preserve the confidentiality of \\(g^{ab}\\) in case the signature allows for message recovery (e.g., [RSA with EMSR-PSS](https://web.archive.org/web/20170810025803/http://grouper.ieee.org/groups/1363/P1363a/contributions/pss-submission.pdf) -- [stop using RSA](https://blog.trailofbits.com/2019/07/08/fuck-rsa/)).

However, Photuris also has an identity misbinding attack if the signature allows for message recovery. If an attacker can recover the signature message then the attacker can sign the message with their private key for a registered public identity which will successfully authenticate.

Additionally, Photuris potentially leaks the hash of \\(g^{ab}\\) which can allow an eavesdropper to derive the symmetric key where:

$$
\text{K}\_s = \text{HMAC-MD5}(\text{MD5}(g^{ab}))
$$

[This article](https://soatok.blog/2020/11/27/the-subtle-hazards-of-real-world-cryptography/) has a good explanation of why this is the case.

**In summary:** the key exchange must bind the identities to the signatures -- verifying the identity of the signer.

## ISO

The ISO IKE protocol is capable of providing an authenticated key exchange but does not protect the identities of the peers.

$$
\begin{eqnarray*}
\text{A} \xrightarrow{A,\\,g^x} \text{B} \\\\
\text{A} \xleftarrow{B,\\,g^y,\\,\text{SIG}\_\text{B}(g^x,\\,g^y,\\,A)} \text{B} \\\\
\text{A} \xrightarrow{\text{SIG}\_\text{B}(g^y,\\,g^x,\\,B)} \text{B}
\end{eqnarray*}
$$

This is suitable for applications where the identities of the peers are not secret (e.g., a network operator needs to passively record network interactions). However, identities are best concealed for the public Internet.

## SIGMA

SIGMA aims to provide the security of ISO IKE while adding identity confidentiality. Critically, SIGMA MACs the peer identities using the derived Diffie-Hellman key to bind the identities to the newly established session and signs the peer parameters to serve as proof of posession of the identity private key. 

$$
\begin{eqnarray*}
\text{A} \xrightarrow{g^x} \text{B} \\\\
\text{A} \xleftarrow{B,\\,g^y,\\,\text{SIG}\_\text{B}(g^x,\\,g^y),\\,\text{MAC}_{K_m}(B)} \text{B} \\\\
\text{A} \xrightarrow{A,\\,\text{SIG}\_\text{A}(g^y,\\,g^x),\\,\text{MAC}\_{K\_m}(A)} \text{B} \\\\
\end{eqnarray*}
$$

Where \\(K\_m\\) is a **handshake key** derived from \\(g^{xy}\\). This is the basis of SIGMA but does _not protect identities_. Additionally, the signature may be over any ephemeral public value (e.g., nonce or Diffie-Hellman value) but it must be ephemeral or a replay attack is possible.

Note: the handshake key should **not** be used as the symmetric key; a new session key should be generated to enforce independence.

### SIGMA-R

SIGMA-R is an extension to the basic SIGMA handshake which protects the identity of the responder (the identity of the initiator is unprotected from an active attacker).

SIGMA-R will delay authenticating identities until the key exchange has occured.

$$
\begin{eqnarray*}
\text{A} \xrightarrow{g^x} \text{B} \\\\
\text{A} \xleftarrow{g^y} \text{B} \\\\
\text{A} \xrightarrow{A,\\,\text{SIG}\_\text{A}(g^y,\\,g^x),\\,\text{MAC}_{K_m}(A)} \text{B} \\\\
\text{A} \xrightarrow{B,\\,\text{SIG}\_\text{B}(g^x,\\,g^y),\\,\text{MAC}\_{K\_m}(B)} \text{B}
\end{eqnarray*}
$$

With the same constraints as the basic SIGMA handshake. However, it is crucial that if it is valid for A to exchange a key with itself then the MAC **must be** bound to an identity specific value to prevent reflection attacks.

```py
initiator_mac_key = HKDF(hashes.SHA256(), info=b"initiator mac key", ...).derive(shared_key)
responder_mac_key = HKDF(hashes.SHA256(), info=b"responder mac key", ...).derive(shared_key)
```

#### Combined MAC and Signature

It is possible to reduce the message size by including the MAC under the signature (the MAC can be calculated by the recipient).

$$
\begin{eqnarray*}
&\vdots& \\\\
\text{A} &\xrightarrow{A,\\,\text{SIG}\_\text{A}(g^y,\\,g^x,\\,\text{MAC}_{K_m}(A))} \text{B} \\\\
\text{A} &\xrightarrow{B,\\,\text{SIG}\_\text{B}(g^x,\\,g^y,\\,\text{MAC}\_{K\_m}(B))} \text{B}
\end{eqnarray*}
$$

Additionally, it is possible to wrap the \\(g^x\\) and \\(g^y\\) parameters under the MAC.

A pseudo-implementation is available [here](https://gist.github.com/birb007/2a1e7f3adbab34a41530037417f782d0).

## Implementation Recommendations

- Use a protocol with verifiable security (e.g., [TLS](https://www.microsoft.com/en-us/research/publication/proving-the-tls-handshake-secure-as-it-is/))
- Use the [Noise Protocol Framework](https://noiseprotocol.org/) to design a secure protocol
- Consider whether SIGMA-R is suitable for your application; compare against the other SIGMA variants.
