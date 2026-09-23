//! Exclusive XML canonicalization (XML-EXC-C14N 1.0) for a signed assertion.
//!
//! The rendering the second gate hashes and the one it verifies the
//! `SignedInfo` under, for the common case: no comments, no
//! `InclusiveNamespaces` prefix list, namespace declarations emitted where
//! visibly used and not already rendered by an ancestor, attributes ordered
//! by namespace then local name, text and attribute values escaped as the
//! specification says. It does not implement the `xml:` attribute inheritance
//! rule or attribute-value whitespace normalization; an assertion needing
//! either does not verify, and the crate documentation says so.

use crate::xml::{Element, Node};

impl Element {
    /// Exclusive canonical form, given the namespaces in scope from ancestors
    /// this element is being canonicalized apart from (empty for a whole
    /// document).
    #[must_use]
    pub fn canonical(&self, in_scope: &[(String, String)]) -> String {
        let mut out = String::new();
        self.render(in_scope, &[], &mut out);
        out
    }

    fn render(
        &self,
        inherited: &[(String, String)],
        rendered: &[(String, String)],
        out: &mut String,
    ) {
        let mut scope = inherited.to_vec();
        for (prefix, uri) in &self.namespaces {
            scope.retain(|(known, _)| known != prefix);
            scope.push((prefix.clone(), uri.clone()));
        }

        let mut used: Vec<String> = vec![self.prefix().to_string()];
        for (name, _) in &self.attributes {
            if let Some((prefix, _)) = name.split_once(':') {
                used.push(prefix.to_string());
            }
        }
        let mut emit: Vec<(String, String)> = Vec::new();
        for prefix in &used {
            if let Some((_, uri)) = scope.iter().rev().find(|(known, _)| known == prefix) {
                let already = rendered.iter().any(|(p, u)| p == prefix && u == uri);
                let queued = emit.iter().any(|(p, _)| p == prefix);
                let empty_default = prefix.is_empty() && uri.is_empty();
                if !(already || queued || empty_default) {
                    emit.push((prefix.clone(), uri.clone()));
                }
            }
        }
        emit.sort_by(|(a, _), (b, _)| a.cmp(b));

        out.push('<');
        out.push_str(&self.name);
        for (prefix, uri) in &emit {
            if prefix.is_empty() {
                out.push_str(" xmlns=\"");
            } else {
                out.push_str(" xmlns:");
                out.push_str(prefix);
                out.push_str("=\"");
            }
            escape_attribute(uri, out);
            out.push('"');
        }
        let mut attributes = self.attributes.clone();
        attributes.sort_by_key(|(name, _)| sort_key(name, &scope));
        for (name, value) in &attributes {
            out.push(' ');
            out.push_str(name);
            out.push_str("=\"");
            escape_attribute(value, out);
            out.push('"');
        }
        out.push('>');

        let mut child_rendered = rendered.to_vec();
        for entry in &emit {
            child_rendered.retain(|(p, _)| p != &entry.0);
            child_rendered.push(entry.clone());
        }
        for child in &self.children {
            match child {
                Node::Element(element) => element.render(&scope, &child_rendered, out),
                Node::Text(text) => escape_text(text, out),
            }
        }
        out.push_str("</");
        out.push_str(&self.name);
        out.push('>');
    }
}

/// The exc-c14n sort key: namespace URI then local name.
fn sort_key(name: &str, scope: &[(String, String)]) -> (String, String) {
    match name.split_once(':') {
        Some((prefix, local)) => {
            let uri = scope
                .iter()
                .rev()
                .find(|(known, _)| known == prefix)
                .map_or(String::new(), |(_, uri)| uri.clone());
            (uri, local.to_string())
        }
        None => (String::new(), name.to_string()),
    }
}

fn escape_text(text: &str, out: &mut String) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
}

fn escape_attribute(value: &str, out: &mut String) {
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::xml::Element;

    #[test]
    fn exclusive_c14n_emits_only_the_namespaces_an_element_uses() {
        let element = Element::parse(concat!(
            r##"<saml:Assertion xmlns:saml="urn:s" xmlns:x="urn:x">"##,
            r##"<ds:SignedInfo xmlns:ds="urn:d"><ds:Reference URI="#_1"/>"##,
            r##"</ds:SignedInfo></saml:Assertion>"##
        ))
        .expect("parsed");
        let signed_info = element.find("SignedInfo").expect("signed info");

        let canonical = signed_info.canonical(&[
            ("saml".to_string(), "urn:s".to_string()),
            ("ds".to_string(), "urn:d".to_string()),
        ]);

        // ds is used and emitted; saml and x are in scope but not used.
        assert!(canonical.starts_with(r#"<ds:SignedInfo xmlns:ds="urn:d">"#));
        assert!(!canonical.contains("urn:s"));
        assert!(canonical.contains(r##"<ds:Reference URI="#_1"></ds:Reference>"##));
    }

    #[test]
    fn text_and_attribute_values_are_escaped_the_canonical_way() {
        let element = Element::parse(r#"<a xmlns="urn:a" t="x&amp;&quot;y">1 &lt; 2 &amp; 3</a>"#)
            .expect("parsed");

        let canonical = element.canonical(&[]);

        assert_eq!(
            canonical,
            r#"<a xmlns="urn:a" t="x&amp;&quot;y">1 &lt; 2 &amp; 3</a>"#
        );
    }
}
