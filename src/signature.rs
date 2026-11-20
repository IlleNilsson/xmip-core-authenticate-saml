//! The enveloped XML signature over an assertion, checked.
//!
//! This covers one profile of XML-DSig (the one identity providers emit for
//! SAML): a single `Signature` enveloped in the `Assertion` as its child, a
//! single `Reference` to the assertion by its `ID`, the transforms
//! enveloped-signature then exclusive c14n, SHA-256 digests and an
//! RSA-SHA256 signature over the canonical `SignedInfo`. Every other shape is
//! refused by name, never passed: another signature algorithm, another
//! canonicalization, another digest, an extra or missing transform, a
//! detached or enveloping signature, more than one reference, or a reference
//! to anything but the assertion.
//!
//! **The signature is the one unsigned part, and holds nothing else.** The
//! enveloped-signature transform takes the `Signature` out before the digest,
//! so whatever stands in it is anyone's: a `Subject` planted in an `Object`
//! or a `KeyInfo` of a genuinely signed assertion is the signature wrapping
//! attack. The `Signature` must hold `SignedInfo`, `SignatureValue` and at
//! most a bare `KeyInfo`, in that order, every element of it in the XML-DSig
//! namespace, and the assertion [`verify`] answers with is read by its
//! children alone (`Element::child`), never by a search.
//!
//! **Which assertion.** The document is the assertion itself, or a
//! `Response` with exactly one `Assertion` child; an assertion anywhere else,
//! or a second one, is refused rather than chosen between.

use crate::xml::Element;
use authenticate::AuthenticateError;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::sha2::{Digest, Sha256};
use rsa::signature::Verifier as _;

const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const EXC_C14N: &str = "xml-exc-c14n";
const RSA_SHA256: &str = "rsa-sha256";
const SHA256: &str = "sha256";
/// The XML-DSig namespace every element of the `Signature` must be in.
pub const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

/// What a bare `KeyInfo` may hold: the key named or carried, and nothing a
/// reader could take for the assertion's own content.
const KEY_INFO: [&str; 12] = [
    "X509Data",
    "X509Certificate",
    "X509SubjectName",
    "X509IssuerSerial",
    "X509IssuerName",
    "X509SerialNumber",
    "X509SKI",
    "KeyName",
    "KeyValue",
    "RSAKeyValue",
    "Modulus",
    "Exponent",
];

type Scope = Vec<(String, String)>;

/// Verify the assertion's enveloped signature against `key`, and answer
/// with the assertion it covers.
///
/// # Errors
///
/// Where the document is not one assertion, the signature is not the
/// profile above or holds anything else, its digest does not match the
/// assertion, or its value does not verify with the key.
pub fn verify<'a>(
    document: &'a Element,
    key: &RsaPublicKey,
) -> Result<&'a Element, AuthenticateError> {
    let (assertion, inherited) = assertion_of(document)?;
    let id = assertion
        .attribute("ID")
        .ok_or_else(|| AuthenticateError::new("the assertion has no ID to sign"))?;

    let signatures: Vec<&Element> = assertion.children_named("Signature").collect();
    let [signature] = signatures.as_slice() else {
        return Err(AuthenticateError::new(
            "the assertion does not carry exactly one Signature as its child",
        ));
    };
    let scope = scope_of(&scope_of(&inherited, assertion), signature);
    check_shape(signature, &scope)?;
    let signed_info = signature
        .child("SignedInfo")
        .ok_or_else(|| AuthenticateError::new("the Signature carries no SignedInfo"))?;

    check_methods(signed_info)?;
    let reference = check_reference(signed_info, id)?;
    check_digest(assertion, &inherited, reference)?;

    let signature_value = decode(signature, "SignatureValue")?;
    let canonical = signed_info.canonical(&scope);
    let verifying = VerifyingKey::<Sha256>::new(key.clone());
    let value = Signature::try_from(signature_value.as_slice())
        .map_err(|_| AuthenticateError::new("the SignatureValue is not an RSA signature"))?;
    verifying
        .verify(canonical.as_bytes(), &value)
        .map_err(|_| {
            AuthenticateError::new(
                "the assertion's signature does not verify with the IdP certificate",
            )
        })?;
    Ok(assertion)
}

/// The one assertion: the document itself, or a `Response`'s one
/// `Assertion` child, with the namespaces in scope above it.
fn assertion_of(document: &Element) -> Result<(&Element, Scope), AuthenticateError> {
    if document.local() == "Assertion" {
        return Ok((document, Vec::new()));
    }
    if document.local() != "Response" {
        return Err(AuthenticateError::new(
            "the document is neither an Assertion nor a Response",
        ));
    }
    let assertions: Vec<&Element> = document.children_named("Assertion").collect();
    match assertions.as_slice() {
        [assertion] => Ok((assertion, scope_of(&[], document))),
        [] => Err(AuthenticateError::new(
            "the Response carries no Assertion as its child",
        )),
        _ => Err(AuthenticateError::new(
            "the Response carries more than one Assertion, and this gate does not choose",
        )),
    }
}

/// `SignedInfo`, `SignatureValue` and at most a bare `KeyInfo`, in that
/// order, every element in the XML-DSig namespace, and no text between.
fn check_shape(signature: &Element, scope: &Scope) -> Result<(), AuthenticateError> {
    let names: Vec<&str> = signature.elements().map(Element::local).collect();
    if !matches!(
        names.as_slice(),
        ["SignedInfo", "SignatureValue"] | ["SignedInfo", "SignatureValue", "KeyInfo"]
    ) || signature.has_text()
    {
        return Err(AuthenticateError::new(format!(
            "the Signature holds {names:?}, and this gate takes SignedInfo, SignatureValue \
             and at most a bare KeyInfo: anything else in the unsigned Signature is refused"
        )));
    }
    in_dsig(signature, scope)?;
    if signature
        .child("SignatureValue")
        .is_some_and(|value| value.elements().next().is_some())
    {
        return Err(AuthenticateError::new(
            "the SignatureValue holds elements, and it is base64 alone",
        ));
    }
    if let Some(key_info) = signature.child("KeyInfo") {
        bare(key_info)?;
    }
    Ok(())
}

/// Every element under `element`, itself included, is in the XML-DSig
/// namespace.
fn in_dsig(element: &Element, scope: &Scope) -> Result<(), AuthenticateError> {
    let scope = scope_of(scope, element);
    let namespace = scope
        .iter()
        .rev()
        .find(|(prefix, _)| prefix == element.prefix())
        .map(|(_, uri)| uri.as_str());
    if namespace != Some(DSIG) {
        return Err(AuthenticateError::new(format!(
            "the Signature holds '{}', which is not in the XML-DSig namespace",
            element.name
        )));
    }
    element
        .elements()
        .try_for_each(|child| in_dsig(child, &scope))
}

/// A `KeyInfo` naming or carrying a key, and nothing else.
fn bare(element: &Element) -> Result<(), AuthenticateError> {
    element.elements().try_for_each(|child| {
        if !KEY_INFO.contains(&child.local()) {
            return Err(AuthenticateError::new(format!(
                "the KeyInfo holds '{}', and a bare KeyInfo names or carries a key alone",
                child.name
            )));
        }
        bare(child)
    })
}

fn check_methods(signed_info: &Element) -> Result<(), AuthenticateError> {
    let algorithm = |element: Option<&Element>| {
        element
            .and_then(|element| element.attribute("Algorithm"))
            .unwrap_or_default()
            .to_ascii_lowercase()
    };
    if !algorithm(signed_info.child("CanonicalizationMethod")).contains(EXC_C14N) {
        return Err(AuthenticateError::new(
            "the SignedInfo is not canonicalized with exclusive c14n, which is all this gate reads",
        ));
    }
    if !algorithm(signed_info.child("SignatureMethod")).contains(RSA_SHA256) {
        return Err(AuthenticateError::new(
            "the signature method is not RSA-SHA256, which is all this gate verifies",
        ));
    }
    let digest = signed_info.at(&["Reference", "DigestMethod"]);
    if !algorithm(digest).contains(SHA256) {
        return Err(AuthenticateError::new(
            "the digest method is not SHA-256, which is all this gate verifies",
        ));
    }
    Ok(())
}

fn check_reference<'a>(
    signed_info: &'a Element,
    id: &str,
) -> Result<&'a Element, AuthenticateError> {
    let references: Vec<&Element> = signed_info.children_named("Reference").collect();
    let [reference] = references.as_slice() else {
        return Err(AuthenticateError::new(
            "the SignedInfo does not have exactly one Reference, which this profile requires",
        ));
    };
    let uri = reference.attribute("URI").unwrap_or_default();
    if uri != format!("#{id}") {
        return Err(AuthenticateError::new(format!(
            "the signature's Reference is '{uri}' and not the assertion '#{id}'"
        )));
    }
    let transforms: Vec<String> = reference
        .child("Transforms")
        .into_iter()
        .flat_map(|transforms| transforms.children_named("Transform"))
        .map(|element| {
            element
                .attribute("Algorithm")
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    let enveloped = transforms.iter().any(|algorithm| algorithm == ENVELOPED);
    let canonical = transforms
        .iter()
        .any(|algorithm| algorithm.contains(EXC_C14N));
    let unknown = transforms
        .iter()
        .find(|algorithm| *algorithm != ENVELOPED && !algorithm.contains(EXC_C14N));
    if let Some(other) = unknown {
        return Err(AuthenticateError::new(format!(
            "the Reference carries the transform '{other}', which this gate does not apply"
        )));
    }
    if !enveloped || !canonical {
        return Err(AuthenticateError::new(
            "the Reference is not enveloped-signature then exclusive c14n, which this gate applies",
        ));
    }
    Ok(reference)
}

fn check_digest(
    assertion: &Element,
    inherited: &[(String, String)],
    reference: &Element,
) -> Result<(), AuthenticateError> {
    let mut signed = assertion.clone();
    signed.remove_child(&|element| element.local() == "Signature");
    let canonical = signed.canonical(inherited);
    let digest = Sha256::digest(canonical.as_bytes());

    let claimed = reference
        .child("DigestValue")
        .map(Element::text)
        .ok_or_else(|| AuthenticateError::new("the Reference carries no DigestValue"))?;
    let claimed = codec::base64::decode(claimed.trim())
        .map_err(|_| AuthenticateError::new("the DigestValue is not base64"))?;
    if digest[..] != claimed[..] {
        return Err(AuthenticateError::new(
            "the assertion's digest does not match the signed DigestValue: it was altered, \
             or its canonical form is one this gate does not reproduce",
        ));
    }
    Ok(())
}

fn decode(signature: &Element, local: &str) -> Result<Vec<u8>, AuthenticateError> {
    let text = signature
        .child(local)
        .map(Element::text)
        .ok_or_else(|| AuthenticateError::new(format!("the Signature carries no {local}")))?;
    codec::base64::decode(&text.split_whitespace().collect::<String>())
        .map_err(|_| AuthenticateError::new(format!("the {local} is not base64")))
}

/// The namespaces in scope at an element, its own added to what it
/// inherited.
fn scope_of(inherited: &[(String, String)], element: &Element) -> Scope {
    let mut scope = inherited.to_vec();
    for (prefix, uri) in &element.namespaces {
        scope.retain(|(known, _)| known != prefix);
        scope.push((prefix.clone(), uri.clone()));
    }
    scope
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};

    const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

    /// An assertion signed the way this gate verifies, from `body` (the
    /// children after the Signature), for `id`.
    pub(crate) fn signed_assertion(key: &RsaPrivateKey, id: &str, body: &str) -> String {
        signed_with(key, id, body, "")
    }

    /// The same, `extra` written into the Signature after its value: where
    /// an attacker writes, since the Signature is not signed.
    pub(crate) fn signed_with(key: &RsaPrivateKey, id: &str, body: &str, extra: &str) -> String {
        let assertion = |signature: &str| {
            format!(
                concat!(
                    r#"<saml:Assertion xmlns:saml="{SAML_NS}" xmlns:ds="{DS_NS}" ID="{id}">"#,
                    r#"{signature}{body}</saml:Assertion>"#
                ),
                SAML_NS = SAML_NS,
                DS_NS = DSIG,
                id = id,
                signature = signature,
                body = body
            )
        };
        // Digest over the assertion with an empty Signature element removed.
        let without = Element::parse(&assertion("<ds:Signature></ds:Signature>")).expect("xml");
        let mut bare = without.clone();
        bare.remove_child(&|element| element.local() == "Signature");
        let digest = codec::base64::encode(&Sha256::digest(bare.canonical(&[]).as_bytes()));

        let signed_info = signed_info(id, &digest);
        // Canonical SignedInfo, in scope: saml and ds from the Assertion.
        let scope = [
            ("saml".to_string(), SAML_NS.to_string()),
            ("ds".to_string(), DSIG.to_string()),
        ];
        let element = Element::parse(&format!(
            concat!(
                r#"<saml:Assertion xmlns:saml="{SAML_NS}" xmlns:ds="{DS_NS}">"#,
                r#"{signed_info}</saml:Assertion>"#
            ),
            SAML_NS = SAML_NS,
            DS_NS = DSIG,
            signed_info = signed_info
        ))
        .expect("xml");
        let canonical = element.child("SignedInfo").expect("si").canonical(&scope);
        let signer = SigningKey::<Sha256>::new(key.clone());
        let value = codec::base64::encode(&signer.sign(canonical.as_bytes()).to_vec());
        let signature = format!(
            concat!(
                r#"<ds:Signature>{signed_info}"#,
                r#"<ds:SignatureValue>{value}</ds:SignatureValue>{extra}</ds:Signature>"#
            ),
            signed_info = signed_info,
            value = value,
            extra = extra
        );
        assertion(&signature)
    }

    /// A `SignedInfo` referencing the assertion `id` with `digest`.
    fn signed_info(id: &str, digest: &str) -> String {
        format!(
            concat!(
                r##"<ds:SignedInfo><ds:CanonicalizationMethod "##,
                r##"Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">"##,
                r##"</ds:CanonicalizationMethod><ds:SignatureMethod "##,
                r##"Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256">"##,
                r##"</ds:SignatureMethod><ds:Reference URI="#{id}"><ds:Transforms>"##,
                r##"<ds:Transform "##,
                r##"Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature">"##,
                r##"</ds:Transform><ds:Transform "##,
                r##"Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>"##,
                r##"</ds:Transforms><ds:DigestMethod "##,
                r##"Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>"##,
                r##"<ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
            ),
            id = id,
            digest = digest
        )
    }

    fn key() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("a key")
    }

    /// One DER element.
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut element = vec![tag];
        if content.len() < 0x80 {
            element.push(u8::try_from(content.len()).expect("short"));
        } else {
            let length = u32::try_from(content.len())
                .expect("a length")
                .to_be_bytes();
            let start = length.iter().take_while(|octet| **octet == 0).count();
            element.push(0x80 | u8::try_from(4 - start).expect("at most four"));
            element.extend_from_slice(&length[start..]);
        }
        element.extend_from_slice(content);
        element
    }

    /// A minimal self-signed X.509 certificate carrying the key, in PEM — its
    /// own signature is not checked by this gate, so it need not be valid.
    pub(crate) fn self_signed_certificate(private: &RsaPrivateKey) -> String {
        use rsa::pkcs8::EncodePublicKey;
        let spki = RsaPublicKey::from(private)
            .to_public_key_der()
            .expect("an SPKI")
            .as_bytes()
            .to_vec();
        let sha256_rsa = der(
            0x06,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
        );
        let mut algorithm = sha256_rsa.clone();
        algorithm.extend(der(0x05, &[])); // NULL
        let algorithm = der(0x30, &algorithm);
        let name = der(0x30, &[]);
        let mut validity = der(0x17, b"700101000000Z");
        validity.extend(der(0x17, b"491231235959Z"));
        let validity = der(0x30, &validity);

        let mut tbs = der(0xA0, &der(0x02, &[0x02])); // version 2 (v3)
        tbs.extend(der(0x02, &[0x01])); // serial
        tbs.extend(algorithm.clone());
        tbs.extend(name.clone());
        tbs.extend(validity);
        tbs.extend(name);
        tbs.extend_from_slice(&spki);
        let tbs = der(0x30, &tbs);

        let mut signature = vec![0u8]; // no unused bits
        signature.extend_from_slice(&[0u8; 256]);
        let mut certificate = tbs;
        certificate.extend(algorithm);
        certificate.extend(der(0x03, &signature));
        let certificate = der(0x30, &certificate);

        let body = codec::base64::encode(&certificate);
        let wrapped = body
            .as_bytes()
            .chunks(64)
            .map(|line| core::str::from_utf8(line).expect("ascii"))
            .collect::<Vec<_>>()
            .join("\n");
        format!("-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n")
    }

    #[test]
    fn a_correctly_signed_assertion_verifies_and_is_the_one_answered() {
        let private = key();
        let public = RsaPublicKey::from(&private);
        let xml = signed_assertion(&private, "_a1", "<saml:Issuer>idp</saml:Issuer>");
        let document = Element::parse(&xml).expect("xml");

        let assertion = verify(&document, &public).expect("verified");

        assert_eq!(assertion.attribute("ID"), Some("_a1"));
    }

    #[test]
    fn a_subject_planted_in_the_unsigned_signature_is_refused() {
        // The signature wrapping attack: the assertion is genuinely signed,
        // and a Subject written into the Signature, which the digest leaves
        // out, would be read by a search before the real one.
        let private = key();
        let public = RsaPublicKey::from(&private);
        let planted = "<saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>";
        for extra in [
            format!("<ds:Object>{planted}</ds:Object>"),
            format!("<ds:KeyInfo>{planted}</ds:KeyInfo>"),
            format!("<ds:KeyInfo><ds:X509Data>{planted}</ds:X509Data></ds:KeyInfo>"),
        ] {
            let xml = signed_with(&private, "_a1", "<saml:Issuer>idp</saml:Issuer>", &extra);
            let document = Element::parse(&xml).expect("xml");

            let failure = verify(&document, &public).expect_err("wrapped");

            assert!(
                failure.message.contains("Signature holds")
                    || failure.message.contains("KeyInfo holds")
                    || failure.message.contains("XML-DSig namespace"),
                "{failure}"
            );
        }
    }

    #[test]
    fn a_bare_key_info_is_taken() {
        let private = key();
        let public = RsaPublicKey::from(&private);
        let key_info = "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIB</ds:X509Certificate>\
             </ds:X509Data></ds:KeyInfo>";
        let xml = signed_with(&private, "_a1", "<saml:Issuer>idp</saml:Issuer>", key_info);
        let document = Element::parse(&xml).expect("xml");

        assert!(verify(&document, &public).is_ok());
    }

    #[test]
    fn a_response_with_a_second_assertion_beside_the_signed_one_is_refused() {
        let private = key();
        let public = RsaPublicKey::from(&private);
        let signed = signed_assertion(&private, "_a1", "<saml:Issuer>idp</saml:Issuer>");
        let forged = format!(r#"<saml:Assertion xmlns:saml="{SAML_NS}" ID="_evil"/>"#);
        let xml =
            format!("<samlp:Response xmlns:samlp=\"urn:p\">{forged}{signed}</samlp:Response>");
        let document = Element::parse(&xml).expect("xml");

        let failure = verify(&document, &public).expect_err("two assertions");

        assert!(
            failure.message.contains("more than one Assertion"),
            "{failure}"
        );
    }

    #[test]
    fn a_tampered_assertion_fails_its_digest() {
        let private = key();
        let public = RsaPublicKey::from(&private);
        let xml = signed_assertion(&private, "_a1", "<saml:Issuer>idp</saml:Issuer>")
            .replace("idp", "evil");
        let document = Element::parse(&xml).expect("xml");

        let failure = verify(&document, &public).expect_err("refused");

        assert!(failure.message.contains("digest does not match"));
    }

    #[test]
    fn a_signature_by_another_key_does_not_verify() {
        let public = RsaPublicKey::from(&key());
        let xml = signed_assertion(&key(), "_a1", "<saml:Issuer>idp</saml:Issuer>");
        let document = Element::parse(&xml).expect("xml");

        let failure = verify(&document, &public).expect_err("refused");

        assert!(failure.message.contains("does not verify with the IdP"));
    }

    #[test]
    fn a_reference_to_another_element_is_refused() {
        let private = key();
        let public = RsaPublicKey::from(&private);
        let xml = signed_assertion(&private, "_a1", "<saml:Issuer>idp</saml:Issuer>")
            .replace("#_a1", "#_other");
        let document = Element::parse(&xml).expect("xml");

        let failure = verify(&document, &public).expect_err("refused");

        assert!(failure.message.contains("Reference"));
    }
}
