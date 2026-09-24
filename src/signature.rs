//! The enveloped XML signature over an assertion, checked.
//!
//! This covers one profile of XML-DSig (the one identity providers emit for
//! SAML): a single `Signature` enveloped in the `Assertion`, a single
//! `Reference` to the assertion by its `ID`, the transforms
//! enveloped-signature then exclusive c14n, SHA-256 digests and an
//! RSA-SHA256 signature over the canonical `SignedInfo`. Every other shape is
//! refused by name, never passed: another signature algorithm, another
//! canonicalization, another digest, an extra or missing transform, a
//! detached or enveloping signature, more than one reference, or a reference
//! to anything but the assertion.

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

/// Verify the assertion's enveloped signature against `key`.
///
/// # Errors
///
/// Where the signature is not the profile above, its digest does not match
/// the assertion, or its value does not verify with the key.
pub fn verify(document: &Element, key: &RsaPublicKey) -> Result<(), AuthenticateError> {
    let (assertion, inherited) =
        locate(document, &[], &|element| element.local() == "Assertion")
            .ok_or_else(|| AuthenticateError::new("the document carries no Assertion"))?;
    let id = assertion
        .attribute("ID")
        .ok_or_else(|| AuthenticateError::new("the assertion has no ID to sign"))?;

    let (signature, signed_info_scope) = locate(assertion, &inherited, &|element| {
        element.local() == "Signature"
    })
    .ok_or_else(|| AuthenticateError::new("the assertion carries no Signature"))?;
    let signed_info = signature
        .find("SignedInfo")
        .ok_or_else(|| AuthenticateError::new("the Signature carries no SignedInfo"))?;

    check_methods(signed_info)?;
    check_reference(signed_info, id)?;
    check_digest(assertion, &inherited, signed_info)?;

    let signature_value = decode(signature, "SignatureValue")?;
    let scope = scope_of(&signed_info_scope, signature);
    let canonical = signed_info.canonical(&scope);
    let verifying = VerifyingKey::<Sha256>::new(key.clone());
    let signature = Signature::try_from(signature_value.as_slice())
        .map_err(|_| AuthenticateError::new("the SignatureValue is not an RSA signature"))?;
    verifying
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| {
            AuthenticateError::new(
                "the assertion's signature does not verify with the IdP certificate",
            )
        })
}

fn check_methods(signed_info: &Element) -> Result<(), AuthenticateError> {
    let algorithm = |local: &str| {
        signed_info
            .find(local)
            .and_then(|element| element.attribute("Algorithm"))
            .unwrap_or_default()
            .to_ascii_lowercase()
    };
    if !algorithm("CanonicalizationMethod").contains(EXC_C14N) {
        return Err(AuthenticateError::new(
            "the SignedInfo is not canonicalized with exclusive c14n, which is all this gate reads",
        ));
    }
    if !algorithm("SignatureMethod").contains(RSA_SHA256) {
        return Err(AuthenticateError::new(
            "the signature method is not RSA-SHA256, which is all this gate verifies",
        ));
    }
    if !algorithm("DigestMethod").contains(SHA256) {
        return Err(AuthenticateError::new(
            "the digest method is not SHA-256, which is all this gate verifies",
        ));
    }
    Ok(())
}

fn check_reference(signed_info: &Element, id: &str) -> Result<(), AuthenticateError> {
    let references: Vec<&Element> = signed_info
        .elements()
        .filter(|element| element.local() == "Reference")
        .collect();
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
        .find("Transforms")
        .into_iter()
        .flat_map(Element::elements)
        .filter(|element| element.local() == "Transform")
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
    Ok(())
}

fn check_digest(
    assertion: &Element,
    inherited: &[(String, String)],
    signed_info: &Element,
) -> Result<(), AuthenticateError> {
    let mut signed = assertion.clone();
    signed.remove_first(&|element| element.local() == "Signature");
    let canonical = signed.canonical(inherited);
    let digest = Sha256::digest(canonical.as_bytes());

    let claimed = signed_info
        .find("DigestValue")
        .map(Element::text)
        .ok_or_else(|| AuthenticateError::new("the Reference carries no DigestValue"))?;
    let claimed = codec::base64::decode(claimed.trim())
        .map_err(|_| AuthenticateError::new("the DigestValue is not base64"))?;
    if digest.as_slice() != claimed.as_slice() {
        return Err(AuthenticateError::new(
            "the assertion's digest does not match the signed DigestValue: it was altered, \
             or its canonical form is one this gate does not reproduce",
        ));
    }
    Ok(())
}

fn decode(signature: &Element, local: &str) -> Result<Vec<u8>, AuthenticateError> {
    let text = signature
        .find(local)
        .map(Element::text)
        .ok_or_else(|| AuthenticateError::new(format!("the Signature carries no {local}")))?;
    codec::base64::decode(&text.split_whitespace().collect::<String>())
        .map_err(|_| AuthenticateError::new(format!("the {local} is not base64")))
}

/// The namespaces in scope at an element the search located, its own added
/// to what it inherited.
fn scope_of(inherited: &[(String, String)], element: &Element) -> Vec<(String, String)> {
    let mut scope = inherited.to_vec();
    for (prefix, uri) in &element.namespaces {
        scope.retain(|(known, _)| known != prefix);
        scope.push((prefix.clone(), uri.clone()));
    }
    scope
}

/// Find the first descendant for which `predicate` holds, returning it and
/// the namespaces in scope from its ancestors (not its own).
fn locate<'a>(
    element: &'a Element,
    inherited: &[(String, String)],
    predicate: &impl Fn(&Element) -> bool,
) -> Option<(&'a Element, Vec<(String, String)>)> {
    if predicate(element) {
        return Some((element, inherited.to_vec()));
    }
    let scope = scope_of(inherited, element);
    element
        .elements()
        .find_map(|child| locate(child, &scope, predicate))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};

    const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
    const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

    /// An assertion signed the way this gate verifies, from `body` (the
    /// children between Issuer and the close), for `id`.
    pub(crate) fn signed_assertion(key: &RsaPrivateKey, id: &str, body: &str) -> String {
        let assertion = |signature: &str| {
            format!(
                concat!(
                    r#"<saml:Assertion xmlns:saml="{SAML_NS}" xmlns:ds="{DS_NS}" ID="{id}">"#,
                    r#"{signature}{body}</saml:Assertion>"#
                ),
                SAML_NS = SAML_NS,
                DS_NS = DS_NS,
                id = id,
                signature = signature,
                body = body
            )
        };
        // Digest over the assertion with an empty Signature element removed.
        let without = Element::parse(&assertion("<ds:Signature></ds:Signature>")).expect("xml");
        let mut bare = without.clone();
        bare.remove_first(&|element| element.local() == "Signature");
        let digest = codec::base64::encode(&Sha256::digest(bare.canonical(&[]).as_bytes()));

        let signed_info = signed_info(id, &digest);
        // Canonical SignedInfo, in scope: saml and ds from the Assertion.
        let scope = [
            ("saml".to_string(), SAML_NS.to_string()),
            ("ds".to_string(), DS_NS.to_string()),
        ];
        let element = Element::parse(&format!(
            concat!(
                r#"<saml:Assertion xmlns:saml="{SAML_NS}" xmlns:ds="{DS_NS}">"#,
                r#"{signed_info}</saml:Assertion>"#
            ),
            SAML_NS = SAML_NS,
            DS_NS = DS_NS,
            signed_info = signed_info
        ))
        .expect("xml");
        let canonical = element.find("SignedInfo").expect("si").canonical(&scope);
        let signer = SigningKey::<Sha256>::new(key.clone());
        let value = codec::base64::encode(&signer.sign(canonical.as_bytes()).to_vec());
        let signature = format!(
            concat!(
                r#"<ds:Signature>{signed_info}"#,
                r#"<ds:SignatureValue>{value}</ds:SignatureValue></ds:Signature>"#
            ),
            signed_info = signed_info,
            value = value
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
    fn a_correctly_signed_assertion_verifies() {
        let private = key();
        let public = RsaPublicKey::from(&private);
        let xml = signed_assertion(&private, "_a1", "<saml:Issuer>idp</saml:Issuer>");
        let document = Element::parse(&xml).expect("xml");

        assert!(verify(&document, &public).is_ok());
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
