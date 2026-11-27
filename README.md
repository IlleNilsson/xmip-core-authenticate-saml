# xmip-core-authenticate-saml

Authenticate by saml: verifies an assertion's signature and conditions against the `IdP` certificate. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

It verifies an enveloped XML signature inside the assertion — RSA-SHA256 over
the exclusively canonicalized `SignedInfo`, SHA-256 over the assertion without
its `Signature` — against the IdP certificate held as configuration, its key
read by the estate's one certificate reader (`tls::certificate`) and its PEM
by `codec::pem` (ADR-0033, amendment 2026-11-13). The
document is the assertion, or a `Response` with exactly one `Assertion`
child; the `Signature` is the assertion's child and holds `SignedInfo`,
`SignatureValue` and at most a bare `KeyInfo`, all in the XML-DSig
namespace, so nothing can be planted in the one part the signature does not
cover. What the assertion says is then read from its own children, never by
a search: the issuer and the subject, mandatory `Conditions` with a
`NotOnOrAfter` and an `AudienceRestriction` naming this node, and a bearer
`SubjectConfirmation` whose data has not expired. The issuer and audience are
required when the verifier is made, and the issuer, audience and expiry
checks are the capability's `authenticate::claims`. An assertion that proves
is spent by its `ID`, and refused when presented again before it expires.
The parser caps nesting before anything is verified.

It covers a stated subset of exclusive canonicalization and refuses
everything outside it by name: other algorithms, other transforms, a
signature on the `Response` only, encrypted assertions, comments, processing
instructions and CDATA. The confirmation's `Recipient` and `InResponseTo` are
not checked.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
