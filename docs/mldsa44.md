# ML-DSA-44 agent identities

Set `key_type = mldsa44` to generate ML-DSA-44 identities with OpenSSL 3.5 or
later and a Ruby OpenSSL binding that supports ML-DSA signing (tested with
Ruby OpenSSL 4.0.2). RSA remains the default.

The shared private-key writer saves ML-DSA-44 keys as seed-only PKCS#8. Inside
`PrivateKeyInfo.privateKey`, the payload is an implicit context-specific `[0]`
containing exactly 32 seed bytes. It does not include the 2,560-byte expanded
private key. Reloading reconstructs the same public and private key pair.

The writer invokes the OpenSSL executable beside Ruby (the bundled executable
in agent packages, or `openssl` on PATH for source installations), passing
`pkey -provparam ml-dsa.output_formats=seed-only`. This sets output policy only
inside that child process; no `OPENSSL_CONF`, service override or parent-process
provider configuration is required. Key material travels through stdin and
passwords through a separate private pipe, never command arguments or files.
OpenSSL handles both PKCS#8 encoding and encryption.

Password-protected saves encrypt the seed-only bytes using the existing
PKCS#8 PBES2 settings: AES-128-CBC and PBKDF2-HMAC-SHA256 with 2,048 iterations
and random salt and IV. The CLI accepts passwords up to 1,023 bytes without
NUL, CR or LF; unsupported passwords raise an error before writing instead of
being silently truncated. Serialization finishes before the existing atomic
writer runs; file permissions and write-error handling are unchanged. A key
without a retained 32-byte seed cannot be saved as seed-only and raises an
error before replacing the file.

Enrollment, replacement key generation and CLI CSR generation use this writer.
Certificate renewal reuses the current key. Loading an existing key does not
rewrite its file, including keys containing an expanded representation. Other
key types retain their existing serialization.

Run the crypto and persistence self-check without configuration or preload helpers:

```sh
env -u OPENSSL_CONF -u RUBYOPT -u LD_PRELOAD \
  /opt/puppetlabs/puppet/bin/ruby -Ilib spec/integration/ssl/mldsa_self_check.rb
```

This checks actual file encoding, encrypted output, public-key identity,
signatures, permissions, enrollment/replacement generation and renewal key
preservation. It does not perform network enrollment or a server lifecycle.
