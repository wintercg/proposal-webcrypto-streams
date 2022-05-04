# Streams for the Web Cryptography API

## Problem Statement

The existing [Web Cryptography API][] allows JavaScript applications to perform
cryptographic operations. Because it is implemented by the JavaScript runtime
(e.g., a web browser), it is unaffected by side-channel vulnerabilities that are
inherent to JavaScript and WebAssembly and can utilize hardware acceleration and
advanced security mechanisms.

A major drawback of the existing Web Cryptography API is the lack of support for
streaming operations. For example, it is impossible to compute a digest of a
message unless the message is stored in a single ArrayBuffer, which is
impractical for large messages. Multiple server-side runtimes, namely [Node.js][]
and [Deno][], provide their own APIs that can efficiently process streams of
data, but which are not compatible with other JavaScript runtimes.

## Support streams in the Web Cryptography API

We solve the above problem by adding support for [Streams][Streams Standard] to
the [Web Cryptography API][] specification.

_This is not meant to be a separate or standalone specification. This proposal
should be considered for inclusion in the [Web Cryptography API][] standard._

The `sign`, `verify`, and `digest` functions, which are part of the existing
[`SubtleCrypto`][] interface, are extended. The extended versions allow signing,
verifying signatures, and computing message digests of streams of data,
respectively.

Additionally, the new `EncryptionStream` and `DecryptionStream` classes allow
encrypting and decrypting streams of data.

For more information about the new API, jump to the [Proposed API][].

## Alternatives Considered and Security Implications

This section outlines various considerations related to this proposal, and what
security implications are expected.


### Async iterators versus Streams

Asynchronous iterators are a more generic and less restrictive interface
compared to [Streams][Streams Standard]. Synchronous and asynchronous iterators
can be as simple as a generator function that yields any number of chunks. Both
WHATWG Streams and Node.js streams can be used as asynchronous iterators, i.e.,
any API that accepts arbitrary asynchronous iterators can process both WHATWG and
Node.js streams.

Iterators can also be used to pass multiple parts of a message when all parts
are already in memory. Using WHATWG Streams makes this use case more
complicated.

On the other hand, WHATWG Streams leave more opportunities for optimization.
Runtimes can optimize data flows between built-in types of stream more
efficiently than when using async iterators that force data flow into a specific
pattern. Such optimizations are not only beneficial for performance but
potentially also allow runtimes to avoid copying sensitive data to the
JavaScript heap when transferring data between streams.

Streams are also naturally designed to be composable, for example, by
piping a stream of data into multiple concurrent pipelines.

With the planned addition of [`ReadableStream.from`][], it will also be possible
to wrap compatible async iterables in a [`ReadableStream`][].

Where the output of an operation is a stream, any Stream is also an async
iterable, so there is no reason to use a less specific output type than a
Stream.

Streams play a large role in recent web standards, including
[`TextEncoderStream`][], [`TextDecoderStream`][], [`CompressionStream`][],
[`DecompressionStream`][], [`fetch`][], [`WebSocketStream`][], etc. Even if only
for consistency with other web standards, streams appear to be a
reasonable design choice.

### Security concerns related to authenticated decryption

A major concern arises when considering the addition of a streaming interface
for authenticated encryption/decryption. Most importantly, this affects AES-GCM.
(While AES-CCM is widely used, it is not currently available through the
[Web Cryptography API][]. By design, AES-CCM does not allow streaming
operations, and thus does not need to be considered here even if AES-CCM becomes
available through the Web Cryptography API.)

In accordance with [SP 800-38D][], an implementation of AES-GCM decryption
should emit the plaintext if and only if the authentication tag was verified
successfully. In other words, an implementation should not output the plaintext
until it has verified the authenticity and integrity of the ciphertext, which
makes streaming decryption infeasible for large messages.

Nevertheless, unlike AES-CCM, the GCM block cipher mode of operation allows
processing data in small chunks, and many software implementations (e.g.,
[OpenSSL][], [Node.js][]) implement this behavior. Such implementations only
verify the authenticity of the ciphertext at the end of the operation, after the
(potentially inauthentic) plaintext has been disclosed to the application at
least in part.

It is common for application protocols to fragment data streams into smaller
chunks, which are then encrypted and decrypted individually. When using an
authenticated encryption mechanism, such as AES-GCM, this implies verifying the
authenticity of each decrypted chunk. This eliminates the need for streaming
behavior at the cryptographic API layer. Instead, the runtime must allow
cryptographic transforms when transforming a stream of encrypted fragments into
a stream of plaintext fragments. This mechanism is used, for example, by TLS 1.3
(see [Section 5.2 of RFC 8446][]). Authenticated encryption is also used in this
manner in [libsodium's `secretstream` implementation][].

Fragmentation of streams into chunks that are processed separately is not a
universal replacement for streaming APIs. For example, the existing
[Web Cryptography API][] makes it impossible to compute the digest of a stream
of data.

These considerations have led to the exclusion of authenticated ciphers from the
new `EncryptionStream` and `DecryptionStream` classes.

### Additional data in AEAD ciphers

Almost all authenticated encryption algorithms support additional data to be
associated with the encryption or decryption operation, which is not encrypted
itself, but which affects the authentication tag. Decryption will fail (with
high probability) if one attempts to decrypt the ciphertext using different
associated data. Such encryption algorithms belong to the category of
authenticated encryption with associated data (AEAD) algorithms.

This construction leads to two separate inputs, the associated data and the
actual plaintext or ciphertext (depending on whether the operation is encryption
or decryption). While, as discussed in the previous section, allowing streaming
the ciphertext to an unknown destination without verifying the authenticity of
the message first is a security concern, AEAD algorithms can usually process
even large amounts of associated data without negatively impacting their
security properties.

The only officially supported AEAD algorithm is AES-GCM. The use of GCM and GMAC
has been [recommended since 2007][SP 800-38D], where GMAC is characterized as
follows.

> If the GCM input is restricted to data that is not to be encrypted, the
> resulting specialization of GCM, called GMAC, is simply an authentication mode
> on the input data.

Thus, the Web Cryptography API already implicitly supports GMAC. When an empty
plaintext is passed to AES-GCM, the ciphertext only consists of the
authentication tag, thus making GMAC behave like any other message
authentication code (MAC) algorithm, such as the explicitly supported HMAC.

No security issues would arise from allowing a stream of input data to be passed
to AES-GCM for the `additionalData` parameter. However, it is unclear how this
would fit into an extended Web Cryptography API.

The Web Cryptography API could explicitly support GMAC analogous to HMAC, i.e.,
as an algorithm that implements the sign and verify operations. This would
eliminate the need to fit GMAC-specific use cases into potential extensions of
the encrypt and decrypt operations.

This would, however, not cover use cases that rely on large amounts of
associated data and small but non-empty plaintexts. This appears to be an
untypical use case. Additionally, due to the way GCM works, it would lead to
undesirable performance because GCM would need to process large amounts of
associated data for a small chunk of application data. In other words, such use
cases would lead to poor performance, measured in CPU cycles per byte of
plaintext.

In conclusion, no streaming capabilities are added for additional authenticated
data.

### Extendable-output functions (XOFs)

With the newest set of FIPS-approved hash functions, the SHA-3 family of hash
functions has been standardized. In addition to these hash functions, the same
standard specifies SHAKE128 and SHAKE256, which are extendable-output functions
(XOFs). BLAKE2X and BLAKE3 are also extendable-output functions that have been
derived from the SHA-3 candidate BLAKE.

Extendable-output functions allow producing a virtually infinite stream of bytes
from an arbitrarily long input. The SHAKE128 and SHAKE256 functions do not need
to know the length of the output in advance, allowing applications to read any
number of bytes from their output.

As such, extendable-output functions, such as SHAKE128 and SHAKE256, can consume
and produce arbitrarily long streams of data. However, unlike other
cryptographic transform streams (e.g., symmetric stream ciphers), they consume
the entire input stream before producing any output.

At the time of writing, there are no NIST-approved or NIST-recommended uses of
XOFs. Their potential use cases appear to fall into two categories:

1. Short outputs: XOFs can be used instead of hash functions in some cases. This
   is particularly useful when hash-like values of specific, uncommon lengths
   are required. However, XOFs possess properties that might make them
   unsuitable as a replacement for hash functions.
   [Ed448 uses SHAKE256][Section 8.9 of RFC 8032] to produce 114 byte hash
   values. There have also been proposals of MAC and KDF constructions based on
   XOFs.
2. Long outputs: XOFs can be used to create finite or infinite streams of
   pseudo-random values. As such, they can be used to construct stream ciphers
   or as CSPRNGs.

Both Node.js ([nodejs/node#28805][]) and Deno ([denoland/deno_std#1025][]) have
added limited support for XOFs. However, both reuse digest APIs for XOFs and
require users to specify the output length before processing any data. This
allows use cases falling into the first category above, but is generally not
suitable for use cases in the second category.

At this point, it is not our intention to explicitly add support for
extendable-output functions to the Web Cryptography API. However, we want to
ensure that our efforts to add streaming capabilities to the API will not
prevent XOF-compatible designs.

### Data that might only be available at the end of the stream

Operations that require more than one input argument, one of which may be a
potentially long stream of data, pose the question as to the order in which these
arguments should be required. This especially concerns the `sign` and `verify`
operations.

To make this decision, we consider different digital signature algorithms.

#### Algorithms supported by the Web Cryptography API

`RSASSA-PKCS1-v1_5` is specified in [Section 8.2 of RFC 3447][]. The relevant 
algorithm is `EMSA-PKCS1-V1_5-ENCODE`, which is used by the signature generation
and signature verification algorithms. `EMSA-PKCS1-V1_5-ENCODE` does not require
the signer's public or private key to process the input data. The verification
algorithm also does not require the signature before being able to invoke
`EMSA-PKCS1-V1_5-ENCODE`.

`RSA-PSS` is specified in [Section 8.1 of RFC 3447][]. The relevant algorithms
are `EMSA-PSS-ENCODE`, which is used by the signature generation algorithm, and
`EMSA-PSS-VERIFY`, which is used by the signature verification algorithm.
Neither algorithm requires the signer's public or private key to process the
input data. The signature verification requires the signature before being able
to invoke `EMSA-PSS-VERIFY`, however, it can be implemented in a way that avoids
this requirement since `EMSA-PSS-VERIFY` internally only needs a hash value of
the message, not the message itself.

ECDSA is specified in [Section 5.4 of RFC 6090][]. Both the signature generation
algorithm and the signature verification algorithm only use a hash value of the
message, not the message itself.

HMAC is specified in Section 4 of [FIPS 198-1][]. Unfortunately, in order for
Step 6 of the algorithm to be computable without having to buffer the entire
input message, the secret key must be known before any of the message can be
processed. Because it is a symmetric algorithm, the verification operation does
not require the signature from the beginning, but only after computing the HMAC
signature itself.

#### Possible future additions

Poly1305 is specified in [Section 2.5 of RFC 7539][] and is a MAC algorithm that
can process messages in a streaming manner. Like HMAC, it requires the key from
the beginning, both for creating and verifying signatures, but not the signature
when verifying.

GMAC is specified in [NIST SP 800-38D][SP 800-38D] and has been discussed above
as an algorithm that is implicitly supported by the Web Cryptography API, but
which would likely need to be added explicitly in order to allow processing
streams of (additional) data using GMAC. Like HMAC and Poly1305, GMAC requires
the key from the beginning but not the signature.

Ed25519 and Ed448 do not pre-hash the message and are thus not considered for
streaming APIs. Instead, Ed25519ph and Ed448ph should be considered for
inclusion. These variants pre-hash the message, which does not require the key.
For verification, the signature is not required before the hash of the message
has been computed.

#### Existing data formats

It is common for the signature to appear after the message itself. X.509
certificates, for example, begin with the actual certificate contents
(TBSCertificate) followed by the signature. Authenticated encryption algorithms
also commonly use this order, for example, AES-GCM.

Therefore, the streaming API should allow specifying the signature after the
entire message has been consumed.

#### Conclusion

To accommodate symmetric signatures, such as HMAC, Poly1305, and GMAC, the key
must be passed when the operation is initiated.

Technically, for algorithms that do not require the key from the beginning but
only after all input data has been consumed, users could be enabled to pass a
`Promise` that eventually resolves to the key. However, such complications
should be avoided until a use case has demonstrated the need for this feature.

For signature verification, none of the discussed algorithms require knowledge
of the signature before having processed the entire message. Symmetric
signatures simply sign the message using the secret key and compare the computed
signature against the given signature. All relevant asymmetric signature
verification algorithms pre-hash the message and then verify the signature using
only the hash value.

Therefore, the streaming API should not require the signature during
verification until after the entire message has been consumed. An advantage of
this design is that it is consistent with the sign operation that only produces
the signature after having consumed all input.

### API considerations

#### The crypto.getRandomValues function

The existing `getRandomValues` function allows filling an existing
`ArrayBufferView` with random data, i.e., it overwrites all bits belonging to
the `ArrayBufferView` with random bits.

There might be use cases that benefit from a stream that emits random bytes.
However, this should already be possible using existing WHATWG Streams APIs,
e.g., by writing random data to an identity [`TransformStream`][] or by creating
a readable stream that passes random data to any reader, for example, using a
[`ReadableByteStreamController`][].

Even in the absence of the WHATWG Streams API, generator functions can be used
to produce an infinite "stream" of random data both synchronously and
asynchronously.

#### The crypto.subtle API

- `crypto.subtle.encrypt` and `crypto.subtle.decrypt`

  Input stream: yes ✔  
  Output stream: yes ✔  
  Restrictions: block and stream ciphers only, no authenticated block cipher
                modes

  Streaming encryption and decryption capabilities should be added for all
  algorithms that are capable of processing large amounts of data (i.e., block
  and stream ciphers) and whose block cipher mode of operation is not an
  authenticated mode (e.g., GCM or CCM). At the time of writing, the only
  algorithms that belong in this category are AES-CTR and AES-CBC.

  Neither AES-CTR nor AES-CBC can reliably detect the premature end of a stream.
  While AES-CTR decryption will never result in an error of any kind, AES-CBC
  may fail due to invalid padding.
- `crypto.subtle.sign` and `crypto.subtle.verify`

  Input stream: yes ✔  
  Output stream: no ✘  
  Restrictions: pre-hashing algorithms only

  Streaming signature and verification capabilities should be added for all
  algorithms that pre-hash their input. At the time of writing, this applies to
  all algorithms that support the sign and verify operations, i.e.,
  `RSASSA-PKCS1-v1_5`, `RSA-PSS`, `ECDSA`, and `HMAC`.

  Algorithms that do not pre-hash their input include Ed25519 and Ed448. These
  are currently not supported by the Web Cryptography API but
  [may be in the future](webcrypto-secure-curves). No streaming capabilities
  should be added for such algorithms. Instead, pre-hashing variants of such
  algorithms should be considered for inclusion in the standard. For example,
  Ed25519ph and Ed448ph are pre-hashing variants of Ed25519 and Ed448,
  respectively.

  Signatures tend to be small. Even signatures produced by algorithms that
  resist attacks that utilize quantum computers
  [tend to be small][pq-signature-sizes], i.e., in the order of kilobytes. Thus,
  no streaming capabilities are planned for the output of `crypto.subtle.sign`.

  Signature verification produces no noteworthy output other than the
  authenticity of the message (or lack thereof). Thus, `crypto.subtle.verify`
  will not produce output in a streaming manner. Similarly, it will not receive
  the signature as a stream, for the same reason crypto.subtle.sign does not
  emit signatures as streams.
- `crypto.subtle.digest`

  Input stream: yes ✔  
  Output stream: no ✘  
  Restrictions: none

  Streaming capabilities should be added to `crypto.subtle.digest` in order to
  efficiently compute digests of large amounts of data. No restrictions apply to
  the set of hash algorithms.

  Future versions of the Web Cryptography API might support extendable-output
  functions (XOFs), such as SHAKE256. Such functions can process arbitrarily
  large inputs and produce arbitrarily long outputs. As such, XOFs could
  particularly benefit from streaming API capabilities. However, most of the
  real-world use cases of XOFs use fixed, small output lengths (e.g., in the
  construction of Ed448). Supporting such use cases would thus only require a
  parameterized algorithm object being passed to `crypto.subtle.digest`.
  However, if the Web Cryptography API intends to support arbitrarily long or
  even infinite XOF outputs, a new API will need to be added that supports both
  input and output streams, either as separate streams or as a single
  [`TransformStream`][]. The latter might be unusual in that it would first
  consume the entire input before producing any output. This appears to be a
  highly specialized and uncommon use case at the time of writing.
- `crypto.subtle.generateKey` and `crypto.subtle.deriveKey`

  Input stream: N/A  
  Output stream: N/A  
  Restrictions: N/A

  These functions do not consume or produce byte sequences. Thus, no streaming
  API capabilities should be added.
- `crypto.subtle.deriveBits`

  Input stream: N/A  
  Output stream: no ✘  
  Restrictions: N/A

  This function consumes a `CryptoKey` and produces an `ArrayBuffer`. At the
  time of writing, `ECDH`, `HKDF`, and `PBKDF2` can be used to derive bits from
  a key or password. Of those, only `HKDF` can consume large amounts of input
  data in a streaming manner. The representation of the input material as a
  `CryptoKey` is also incompatible with consuming a stream of data.

  `HKDF` and `PBKDF2` can produce large amounts of data in a streaming manner.
  However, as their name implies, this is not their intended purpose.
  Additionally, `HKDF` is limited to an output size of 16320 bytes even when
  using a 512-bit hash function.

  Based on existing APIs, algorithmic restrictions, and realistic use cases, no
  streaming API capabilities should be added.
- `crypto.subtle.importKey`, `crypto.subtle.exportKey`, `crypto.subtle.wrapKey`,
  and `crypto.subtle.unwrapKey`

  Input stream: no ✘  
  Output stream: no ✘  
  Restrictions: N/A

  These functions consume and produce byte sequences that represent secret,
  public, and private keys. (This does not apply to importing and exporting keys
  in the JWK format.)

  Secret keys can be used for symmetric cryptography and for key derivation.
  Such keys tend to be small. While inputs to key derivation functions (in
  particular, `HKDF`) may be large, they are typically not. See
  `crypto.subtle.deriveKey` above.

  While we do expect the sizes of asymmetric keys to grow significantly with the
  transition toward post-quantum cryptography, we assume that their sizes will
  still allow efficient processing without streaming capabilities.

## Proposed API

This section describes the proposed API, which is meant to modify and complement
the existing Web Cryptography API's [`SubtleCrypto`][] interface.

The following properties of the [`SubtleCrypto`][] interface are modified.

- `crypto.subtle.digest` - The modified `crypto.subtle.digest` function accepts
  a [`BufferSource`][] or a [`ReadableStream`][] as the `data` argument that is
  to be hashed.

  ```
  Promise<any> digest(AlgorithmIdentifier algorithm,
                      BufferSource | ReadableStream data);
  ```
- `crypto.subtle.sign` - The modified `crypto.subtle.sign` function accepts a
  [`BufferSource`][] or a [`ReadableStream`][] as the `data` argument that is to
  be signed.

  ```
  Promise<any> sign(AlgorithmIdentifier algorithm,
                    CryptoKey key,
                    BufferSource | ReadableStream data);
  ```
- `crypto.subtle.verify` - The modified `crypto.subtle.verify` function accepts
  a [`BufferSource`][] or a [`ReadableStream`][] as the `data` argument for
  which the signature is to be verified. Additionally, the `signature` argument
  can be a [`BufferSource`] or a `Promise<BufferSource>`.

  ```
  Promise<any> verify(AlgorithmIdentifier algorithm,
                      CryptoKey key,
                      BufferSource | Promise<BufferSource> signature,
                      BufferSource | ReadableStream data);
  ```

  This allows using the `verify` function regardless of whether the signature is
  known to the caller before or after the input data is.

  The result does not settle before either both the input data stream has ended
  and the signature has resolved, or the input data stream encountered an error
  or the signature rejected. In the latter case, the result rejects. Otherwise,
  it resolves with the verification result.

Additionally, two new classes are added to the global scope.

- `EncryptionStream` - This transform stream allows encrypting a stream of data
  using an unauthenticated cipher. The constructor takes the same arguments as
  `crypto.subtle.encrypt` other than the `data` argument.

  ```
  interface EncryptionStream {
    constructor(AlgorithmIdentifier algorithm, CryptoKey key);
  };
  EncryptionStream includes GenericTransformStream;
  ```

- `DecryptionStream` - This transform stream allows decrypting a stream of data
  using an unauthenticated cipher. The constructor takes the same arguments as
  `crypto.subtle.decrypt` other than the `data` argument.

  ```
  interface DecryptionStream {
    constructor(AlgorithmIdentifier algorithm, CryptoKey key);
  };
  DecryptionStream includes GenericTransformStream;
  ```

## Code Examples

### Digest

```js
const { body } = await fetch('https://http.cat/200');

// Compute a message digest of the response body without awaiting the entire
// body first.
const digest = await crypto.subtle.digest('SHA-256', body);
```

### Encryption and decryption

```js
const { body } = await fetch('https://http.cat/200');

const cipher = new EncryptionStream({
  name: 'AES-CBC',
  iv: myInitializationVector
}, myKey);

const decipher = new DecryptionStream({
  name: 'AES-CBC',
  iv: myInitializationVector
}, myKey);

// Encryption followed by immediate decryption is effectively an identity
// transform stream:
await body.pipeThrough(cipher)
          .pipeThrough(decipher)
          .pipeTo(destination);
```

### Digital signatures

```js
const { body } = await fetch('https://http.cat/200');

const [bodyToSign, bodyToVerify] = body.tee();

// No await here!
const signature = crypto.subtle.sign('HMAC', myKey, bodyToSign);

// Wait for both the signature and the data that the signature is for at the
// same time:
const isValid =
  await crypto.subtle.verify('HMAC', myKey, signature, bodyToVerify);
```

## References

1. [Bug 27755 - Using the Subtle Crypto Interface with Streams][w3c/webcrypto#73]
1. [Streams Standard][]
1. [Web Cryptography API][]

[`BufferSource`]: https://www.w3.org/TR/WebIDL-1/#common-BufferSource
[`CompressionStream`]: https://developer.mozilla.org/en-US/docs/Web/API/CompressionStream
[`DecompressionStream`]: https://developer.mozilla.org/en-US/docs/Web/API/DecompressionStream
[`ReadableStream`]: https://streams.spec.whatwg.org/#readablestream
[`ReadableStream.from`]: https://github.com/whatwg/streams/issues/1018
[`ReadableByteStreamController`]: https://developer.mozilla.org/en-US/docs/Web/API/ReadableByteStreamController
[`SubtleCrypto`]: https://www.w3.org/TR/2017/REC-WebCryptoAPI-20170126/#dfn-SubtleCrypto
[`TextDecoderStream`]: https://developer.mozilla.org/en-US/docs/Web/API/TextDecoderStream
[`TextEncoderStream`]: https://developer.mozilla.org/en-US/docs/Web/API/TextEncoderStream
[`TransformStream`]: https://developer.mozilla.org/en-US/docs/Web/API/TransformStream
[`WebSocketStream`]: https://web.dev/websocketstream/
[`fetch`]: https://developer.mozilla.org/en-US/docs/Web/API/fetch
[Deno]: https://github.com/denoland/deno
[FIPS 198-1]: https://csrc.nist.gov/publications/detail/fips/198/1/final
[Node.js]: https://github.com/nodejs/node
[OpenSSL]: https://github.com/openssl/openssl
[Proposed API]: #proposed-api
[Streams Standard]: https://streams.spec.whatwg.org/
[SP 800-38D]: https://csrc.nist.gov/publications/detail/sp/800-38d/final
[Section 2.5 of RFC 7539]: https://datatracker.ietf.org/doc/html/rfc7539#section-2.5
[Section 5.2 of RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
[Section 5.4 of RFC 6090]: https://datatracker.ietf.org/doc/html/rfc6090#section-5.4
[Section 8.1 of RFC 3447]: https://datatracker.ietf.org/doc/html/rfc3447#section-8.1
[Section 8.2 of RFC 3447]: https://datatracker.ietf.org/doc/html/rfc3447#section-8.2
[Section 8.9 of RFC 8032]: https://datatracker.ietf.org/doc/html/rfc8032#section-8.9
[Web Cryptography API]: https://www.w3.org/TR/2017/REC-WebCryptoAPI-20170126/
[libsodium's `secretstream` implementation]: https://doc.libsodium.org/secret-key_cryptography/secretstream
[denoland/deno_std#1025]: https://github.com/denoland/deno_std/pull/1025
[nodejs/node#28805]: https://github.com/nodejs/node/pull/28805
[pq-signature-sizes]: https://blog.cloudflare.com/sizing-up-post-quantum-signatures/
[w3c/webcrypto#73]: https://github.com/w3c/webcrypto/issues/73
[webcrypto-secure-curves]: https://github.com/twiss/webcrypto-secure-curves
