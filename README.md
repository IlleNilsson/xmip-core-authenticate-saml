# xmip-core-authenticate-saml

Authenticate by saml: verifies an assertion's signature and conditions against the `IdP` metadata. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

It verifies an enveloped XML signature inside the assertion — RSA-SHA256 over
the exclusively canonicalized `SignedInfo`, SHA-256 over the assertion without
its `Signature` — against the IdP certificate held as configuration, then
`NotBefore`, `NotOnOrAfter`, the audience, the issuer and the subject. It covers
a stated subset of exclusive canonicalization and refuses everything outside
it by name: other algorithms, other transforms, a signature on the `Response`
only, encrypted assertions, comments, processing instructions and CDATA.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
