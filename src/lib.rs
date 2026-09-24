#![forbid(unsafe_code)]

//! Authenticate by saml: verifies an assertion's signature and conditions
//! against the `IdP` certificate.
//!
//! The first gate read a SAML assertion's `NameID` and presented it as the
//! claim, with the assertion itself — the posted `SAMLResponse` or the bare
//! element, base64 — riding as the `saml.assertion` proof. This gate opens
//! it: it checks the enveloped XML signature against the identity provider's
//! certificate held as configuration (see [`signature`]), and then the
//! assertion's conditions — `NotBefore` and `NotOnOrAfter` with the
//! configured leeway, the `AudienceRestriction` naming this node, the
//! `Issuer` being the expected provider, and the subject being the value that
//! was claimed. Offline throughout (ADR-0045): the certificate is
//! configuration, and no metadata is fetched.
//!
//! **What of XML-DSig is covered, precisely.** One enveloped `Signature` in
//! the `Assertion`, one `Reference` to the assertion by its `ID`, the
//! transforms enveloped-signature then exclusive c14n, SHA-256 digests, an
//! RSA-SHA256 signature over the canonical `SignedInfo`, and the subset of
//! exclusive canonicalization [`xml`] documents. Everything else is refused
//! by name and never passed: other signature or digest algorithms, other
//! canonicalizations, extra or missing transforms, a detached or enveloping
//! signature, more than one reference, `KeyInfo`-selected keys, encrypted
//! assertions, CDATA, comments and processing instructions. Only an RSA
//! certificate is read; an EC or other `IdP` key is refused. An assertion
//! whose canonical form this gate does not reproduce fails its digest and is
//! refused, not passed — a signature over something read wrong would be worse
//! than a refusal.
//!
//! A node that expects one account says so with
//! [`Verifier::expecting_principal`]: the verified assertion's `NameID`, or
//! its `upn` attribute where the `NameID` is not one, is read as the identify
//! capability's `UserPrincipalName` and must be the same account, however
//! either was spelled (ADR-0054).

pub mod c14n;
pub mod signature;
pub mod xml;

pub use xml::Element;

use authenticate::clock::{Clock, Window};
use authenticate::{AuthenticateError, Authenticator};
use codec::civil::CivilTime;
use context::Verified;
use identify::Presented;
use identify::UserPrincipalName;
use identify::evidence::{self, SAML_ASSERTION};
use identify::saml;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use x509_parser::prelude::{FromDer, X509Certificate};
use xcore::{Mechanism, mechanism};

/// The identity provider's RSA signing key, however it was configured.
#[derive(Clone, Debug)]
pub struct IdpCertificate {
    key: RsaPublicKey,
}

impl IdpCertificate {
    /// The key of an X.509 certificate in PEM (`-----BEGIN CERTIFICATE-----`)
    /// or DER, as `IdP` metadata carries one.
    ///
    /// # Errors
    ///
    /// Where the bytes are not an X.509 certificate, or its key is not RSA.
    pub fn from_certificate(certificate: &[u8]) -> Result<Self, AuthenticateError> {
        let der = to_der(certificate, "CERTIFICATE")?;
        let (_, parsed) = X509Certificate::from_der(&der).map_err(|_| {
            AuthenticateError::new("the IdP certificate is not an X.509 certificate")
        })?;
        let key = RsaPublicKey::from_public_key_der(parsed.public_key().raw).map_err(|_| {
            AuthenticateError::new(
                "the IdP certificate's key is not RSA, which is all this gate reads",
            )
        })?;
        Ok(Self { key })
    }

    /// A bare RSA public key, where the node holds one rather than a whole
    /// certificate.
    #[must_use]
    pub fn from_public_key(key: RsaPublicKey) -> Self {
        Self { key }
    }
}

/// One base64 block to DER: a PEM body between its markers, or the bytes as
/// they are.
fn to_der(bytes: &[u8], label: &str) -> Result<Vec<u8>, AuthenticateError> {
    let text = core::str::from_utf8(bytes).unwrap_or_default();
    let begin = format!("-----BEGIN {label}-----");
    if let Some(start) = text.find(&begin) {
        let body = &text[start + begin.len()..];
        let end = body
            .find("-----END")
            .ok_or_else(|| AuthenticateError::new("the PEM certificate is not closed"))?;
        let base64: String = body[..end].split_whitespace().collect();
        return codec::base64::decode(&base64)
            .map_err(|_| AuthenticateError::new("the PEM certificate body is not base64"));
    }
    Ok(bytes.to_vec())
}

/// The saml authenticator: the `IdP` certificate, the issuer and audience it
/// expects, and how far a clock may be off.
pub struct Verifier {
    certificate: IdpCertificate,
    issuer: Option<String>,
    audience: Option<String>,
    principal: Option<UserPrincipalName>,
    clock: Clock,
}

impl Verifier {
    /// Verifies against this certificate, expecting no issuer or audience,
    /// with sixty seconds of leeway and the system clock.
    #[must_use]
    pub fn new(certificate: IdpCertificate) -> Self {
        Self {
            certificate,
            issuer: None,
            audience: None,
            principal: None,
            clock: Clock::system(60),
        }
    }

    /// Refuse an assertion whose `Issuer` is not this.
    #[must_use]
    pub fn expecting_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Refuse an assertion whose audience does not name this.
    #[must_use]
    pub fn expecting_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Refuse an assertion that does not name this account, in its `NameID`
    /// or else in its `upn` attribute. Any spelling of the account meets it.
    #[must_use]
    pub fn expecting_principal(mut self, principal: UserPrincipalName) -> Self {
        self.principal = Some(principal);
        self
    }

    /// How far a clock may be off before the conditions bite.
    #[must_use]
    pub fn with_leeway(mut self, seconds: i64) -> Self {
        self.clock = self.clock.forgiving(seconds);
        self
    }

    /// Where the time comes from; the tests pin it.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = self.clock.reading(clock);
        self
    }

    /// Where an account is expected, the assertion names it, by the rule both
    /// gates read an assertion's principal by (`identify::saml`).
    fn check_principal(&self, assertion: &Element) -> Result<(), AuthenticateError> {
        let Some(expected) = &self.principal else {
            return Ok(());
        };
        let name_id = assertion.find("Subject").and_then(|s| s.find("NameID"));
        let upn = assertion.find("AttributeStatement").and_then(|statement| {
            statement
                .elements()
                .find(|element| {
                    element.local() == "Attribute"
                        && saml::is_upn_attribute(element.attribute("Name").unwrap_or_default())
                })
                .and_then(|element| element.find("AttributeValue"))
        });
        let named = saml::user_principal(
            &name_id.map(Element::text).unwrap_or_default(),
            name_id.and_then(|element| element.attribute("Format")),
            upn.map(Element::text).as_deref(),
        );
        match named {
            Some(named) if named.is(expected) => Ok(()),
            Some(named) => Err(AuthenticateError::new(format!(
                "the assertion names '{named}' and this node expects '{expected}'"
            ))),
            None => Err(AuthenticateError::new(format!(
                "the assertion carries no user principal name, as its NameID or as a upn \
                 attribute, and this node expects '{expected}'"
            ))),
        }
    }

    fn check_conditions(
        &self,
        assertion: &Element,
        subject: &str,
    ) -> Result<(), AuthenticateError> {
        if let Some(issuer) = &self.issuer {
            let named = assertion
                .elements()
                .find(|element| element.local() == "Issuer")
                .map(Element::text)
                .unwrap_or_default();
            if named != *issuer {
                return Err(AuthenticateError::new(format!(
                    "the assertion's issuer is not '{issuer}'"
                )));
            }
        }

        let name_id = assertion
            .find("Subject")
            .and_then(|s| s.find("NameID"))
            .map(Element::text)
            .unwrap_or_default();
        if name_id != subject {
            return Err(AuthenticateError::new(
                "the assertion's subject is not the claimed value",
            ));
        }

        if let Some(conditions) = assertion.find("Conditions") {
            let at = |name: &str| conditions.attribute(name).map(instant).transpose();
            self.clock
                .admits(Window::between(at("NotBefore")?, at("NotOnOrAfter")?))
                .map_err(|outside| AuthenticateError::new(format!("the assertion {outside}")))?;
            if let Some(audience) = &self.audience {
                let named = conditions
                    .find("Audience")
                    .map(Element::text)
                    .unwrap_or_default();
                if named != *audience {
                    return Err(AuthenticateError::new(format!(
                        "the assertion's audience does not name '{audience}'"
                    )));
                }
            }
        } else if self.audience.is_some() {
            return Err(AuthenticateError::new(
                "the assertion carries no Conditions and this node requires an audience",
            ));
        }
        Ok(())
    }
}

impl Authenticator for Verifier {
    fn mechanism(&self) -> Mechanism {
        mechanism::saml()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        let name = presented.mechanism.name();
        if name != self.mechanism().name() {
            return Err(AuthenticateError::new(format!(
                "'{name}' was presented and this authenticator verifies saml"
            )));
        }
        let encoded = presented.proof(evidence::SAML_ASSERTION).ok_or_else(|| {
            AuthenticateError::new(format!("no {SAML_ASSERTION} proof was presented"))
        })?;
        let bytes = saml::decode(encoded)?;
        let xml = String::from_utf8(bytes)
            .map_err(|_| AuthenticateError::new("the SAML assertion is not UTF-8 XML"))?;
        if xml.contains("EncryptedAssertion") {
            return Err(AuthenticateError::new(
                "the SAML response carries an EncryptedAssertion, which this gate cannot open",
            ));
        }
        let document = Element::parse(&xml)?;

        signature::verify(&document, &self.certificate.key)?;
        let assertion = document
            .find("Assertion")
            .ok_or_else(|| AuthenticateError::new("the document carries no Assertion"))?;
        self.check_conditions(assertion, &presented.value)?;
        self.check_principal(assertion)?;

        Ok(Verified::Proven)
    }
}

/// A SAML `dateTime` — `YYYY-MM-DDThh:mm:ss[.fff]Z` — in seconds since the
/// Unix epoch. A trailing `Z` is required; a fractional second is dropped.
///
/// # Errors
///
/// Where the text is not that shape.
fn instant(text: &str) -> Result<i64, AuthenticateError> {
    let bad = || AuthenticateError::new(format!("'{text}' is not a UTC SAML dateTime"));
    let core = text.strip_suffix('Z').ok_or_else(bad)?;
    let core = core.split('.').next().unwrap_or(core);
    let (date, time) = core.split_once('T').ok_or_else(bad)?;
    let mut date = date.split('-');
    let mut time = time.split(':');
    let next = |part: &mut std::str::Split<'_, char>| {
        part.next()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(bad)
    };
    let year = date
        .next()
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(bad)?;
    let (month, day) = (next(&mut date)?, next(&mut date)?);
    let (hour, minute, second) = (next(&mut time)?, next(&mut time)?, next(&mut time)?);
    let moment = CivilTime::new(year, month, day, hour, minute, second).ok_or_else(bad)?;
    Ok(moment.unix())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::tests::signed_assertion;
    use rsa::RsaPrivateKey;
    use std::fmt::Write as _;

    const NOW: i64 = 1_800_000_000; // 2027-01-15T08:00:00Z.
    const ISSUER: &str = "https://idp.example";
    const AUDIENCE: &str = "https://xmip.example/acs";

    fn key() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("a key")
    }

    fn body(subject: &str, not_before: &str, not_after: &str) -> String {
        format!(
            concat!(
                r#"<saml:Issuer>{ISSUER}</saml:Issuer>"#,
                r#"<saml:Subject><saml:NameID>{subject}</saml:NameID></saml:Subject>"#,
                r#"<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_after}">"#,
                r#"<saml:AudienceRestriction><saml:Audience>{AUDIENCE}</saml:Audience>"#,
                r#"</saml:AudienceRestriction></saml:Conditions>"#
            ),
            ISSUER = ISSUER,
            subject = subject,
            not_before = not_before,
            not_after = not_after,
            AUDIENCE = AUDIENCE
        )
    }

    fn verifier(private: &RsaPrivateKey) -> Verifier {
        let certificate = IdpCertificate::from_public_key(RsaPublicKey::from(private));
        Verifier::new(certificate)
            .expecting_issuer(ISSUER)
            .expecting_audience(AUDIENCE)
            .with_clock(|| NOW)
    }

    fn presented(assertion: &str) -> Presented {
        Presented::passed(mechanism::saml(), "partner-x").with_proof(
            evidence::SAML_ASSERTION,
            codec::base64::encode(assertion.as_bytes()),
        )
    }

    #[test]
    fn a_signed_assertion_within_its_window_is_proven() {
        let private = key();
        let xml = signed_assertion(
            &private,
            "_a1",
            &body("partner-x", "2027-01-15T07:00:00Z", "2027-01-15T09:00:00Z"),
        );

        let verified = verifier(&private).verify(&presented(&xml)).expect("proven");

        assert_eq!(verified, Verified::Proven);
    }

    const UPN: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn";

    /// An assertion for `subject` within its window, its `upn` attribute
    /// naming `upn` where one is given.
    fn naming(private: &RsaPrivateKey, subject: &str, upn: Option<&str>) -> Presented {
        let mut body = body(subject, "2027-01-15T07:00:00Z", "2027-01-15T09:00:00Z");
        if let Some(upn) = upn {
            let _ = write!(
                body,
                concat!(
                    r#"<saml:AttributeStatement><saml:Attribute Name="{}">"#,
                    r#"<saml:AttributeValue>{}</saml:AttributeValue>"#,
                    r#"</saml:Attribute></saml:AttributeStatement>"#
                ),
                UPN, upn
            );
        }
        let xml = signed_assertion(private, "_a1", &body);
        Presented::passed(mechanism::saml(), subject).with_proof(
            evidence::SAML_ASSERTION,
            codec::base64::encode(xml.as_bytes()),
        )
    }

    fn jane() -> UserPrincipalName {
        UserPrincipalName::parse("jane@partnerx").expect("a name")
    }

    #[test]
    fn a_name_id_or_a_upn_attribute_spelled_another_way_is_the_account_expected() {
        let private = key();
        let gate = verifier(&private).expecting_principal(jane());
        let by_name_id = naming(&private, "PARTNERX\\Jane", None);
        let by_attribute = naming(&private, "partner-x", Some("Jane@PartnerX"));

        assert_eq!(gate.verify(&by_name_id).expect("proven"), Verified::Proven);
        assert_eq!(
            gate.verify(&by_attribute).expect("proven"),
            Verified::Proven
        );
    }

    #[test]
    fn an_assertion_naming_another_account_is_refused_naming_both() {
        let private = key();
        let gate = verifier(&private).expecting_principal(jane());
        let other = naming(&private, "mallory@partnerx", None);
        let unnamed = naming(&private, "partner-x", None);

        let refused = gate.verify(&other).expect_err("refused");
        let missing = gate.verify(&unnamed).expect_err("refused");

        assert_eq!(
            refused.message,
            "the assertion names 'mallory@partnerx' and this node expects 'jane@partnerx'"
        );
        assert!(missing.message.contains("carries no user principal name"));
    }

    #[test]
    fn an_assertion_signed_by_another_idp_is_refused() {
        let signer = key();
        let xml = signed_assertion(
            &signer,
            "_a1",
            &body("partner-x", "2027-01-15T07:00:00Z", "2027-01-15T09:00:00Z"),
        );

        let failure = verifier(&key())
            .verify(&presented(&xml))
            .expect_err("refused");

        assert!(failure.message.contains("does not verify with the IdP"));
    }

    #[test]
    fn an_expired_assertion_is_refused_by_its_window() {
        let private = key();
        let xml = signed_assertion(
            &private,
            "_a1",
            &body("partner-x", "2027-01-15T05:00:00Z", "2027-01-15T06:00:00Z"),
        );

        let failure = verifier(&private)
            .verify(&presented(&xml))
            .expect_err("refused");

        assert!(failure.message.contains("expired at"));
    }

    #[test]
    fn an_assertion_for_another_audience_is_refused() {
        let private = key();
        let assertion = signed_assertion(
            &private,
            "_a1",
            &body("partner-x", "2027-01-15T07:00:00Z", "2027-01-15T09:00:00Z"),
        )
        .replace(AUDIENCE, "https://someone.else/acs");

        // The digest now fails first, because the audience is inside the
        // signed assertion; either way it is refused, never passed.
        let failure = verifier(&private)
            .verify(&presented(&assertion))
            .expect_err("refused");

        assert!(failure.message.contains("digest does not match"));
    }

    #[test]
    fn a_subject_that_is_not_the_claim_is_refused() {
        let private = key();
        let xml = signed_assertion(
            &private,
            "_a1",
            &body(
                "someone-else",
                "2027-01-15T07:00:00Z",
                "2027-01-15T09:00:00Z",
            ),
        );

        let failure = verifier(&private)
            .verify(&presented(&xml))
            .expect_err("refused");

        assert!(failure.message.contains("subject is not the claimed value"));
    }

    #[test]
    fn an_encrypted_assertion_is_refused_rather_than_passed() {
        let claim = Presented::passed(mechanism::saml(), "partner-x").with_proof(
            evidence::SAML_ASSERTION,
            codec::base64::encode(
                "<samlp:Response><EncryptedAssertion/></samlp:Response>".as_bytes(),
            ),
        );

        let failure = verifier(&key()).verify(&claim).expect_err("refused");

        assert!(failure.message.contains("EncryptedAssertion"));
    }

    #[test]
    fn another_mechanism_and_a_missing_proof_are_each_refused_by_name() {
        let gate = verifier(&key());
        let other = Presented::passed(mechanism::oidc(), "partner-x");
        let bare = Presented::passed(mechanism::saml(), "partner-x");

        assert!(
            gate.verify(&other)
                .expect_err("refused")
                .message
                .contains("'oidc' was presented")
        );
        assert!(
            gate.verify(&bare)
                .expect_err("refused")
                .message
                .contains("saml.assertion")
        );
    }

    #[test]
    fn an_idp_certificate_in_pem_is_read_for_its_rsa_key() {
        let certificate = crate::signature::tests::self_signed_certificate(&key());

        let read = IdpCertificate::from_certificate(certificate.as_bytes());

        assert!(read.is_ok());
    }

    #[test]
    fn a_saml_datetime_is_seconds_since_the_epoch() {
        assert_eq!(instant("2027-01-15T08:00:00Z").expect("time"), NOW);
        assert_eq!(instant("2027-01-15T08:00:00.500Z").expect("time"), NOW);
        assert!(instant("2027-01-15 08:00:00").is_err());
    }
}
