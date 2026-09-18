//! A small XML reader and the exclusive canonicalization a signed assertion
//! needs, and nothing beyond it.
//!
//! This parses the well-formed subset a SAML assertion is: elements,
//! attributes, text and the five predefined entities, with the XML
//! declaration and comments skipped. It refuses what it does not implement —
//! CDATA sections, character references outside the predefined entities that
//! are not decimal or hex, processing instructions inside the document, and
//! DTDs — rather than mishandle them, because a signature over something read
//! wrong is worse than a refusal.
//!
//! [`Element::canonical`] renders exclusive XML canonicalization (XML-EXC-C14N
//! 1.0) for the common case: no comments, no `InclusiveNamespaces` prefix
//! list, namespace declarations emitted where visibly used and not already
//! rendered by an ancestor, attributes ordered by namespace then local name,
//! text and attribute values escaped as the specification says. It does not
//! implement the `xml:` attribute inheritance rule or attribute-value
//! whitespace normalization; an assertion needing either does not verify, and
//! [`crate`]'s documentation says so.

use authenticate::AuthenticateError;

/// A list of name-value pairs: attributes, or namespace declarations.
type Pairs = Vec<(String, String)>;

/// One element of the tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Element {
    /// The qualified name, `saml:Assertion` or `Assertion`.
    pub name: String,
    /// The `xmlns` and `xmlns:*` declarations on this element, prefix then
    /// URI; the default namespace is the empty prefix.
    pub namespaces: Vec<(String, String)>,
    /// The other attributes, qualified name then unescaped value.
    pub attributes: Vec<(String, String)>,
    /// The element's children in order.
    pub children: Vec<Node>,
}

/// A child: an element or a run of text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Node {
    /// A nested element.
    Element(Element),
    /// Character data, unescaped.
    Text(String),
}

impl Element {
    /// Parse one document into its root element.
    ///
    /// # Errors
    ///
    /// Where the text is not the well-formed subset this reads.
    pub fn parse(xml: &str) -> Result<Self, AuthenticateError> {
        let mut reader = Reader {
            rest: xml.trim_start_matches('\u{feff}'),
        };
        reader.skip_prolog()?;
        let element = reader.element()?;
        reader.skip_trivia()?;
        if !reader.rest.trim().is_empty() {
            return Err(AuthenticateError::new(
                "the XML has content after its root element",
            ));
        }
        Ok(element)
    }

    /// This element's prefix, `saml` in `saml:Assertion`, or the empty
    /// string for a default-namespace or unprefixed name.
    #[must_use]
    pub fn prefix(&self) -> &str {
        self.name.split_once(':').map_or("", |(prefix, _)| prefix)
    }

    /// The local name, `Assertion` in `saml:Assertion`.
    #[must_use]
    pub fn local(&self) -> &str {
        self.name
            .split_once(':')
            .map_or(self.name.as_str(), |(_, local)| local)
    }

    /// One attribute's value by qualified name.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The child elements, text passed over.
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|child| match child {
            Node::Element(element) => Some(element),
            Node::Text(_) => None,
        })
    }

    /// The first descendant with this local name, self included, depth first.
    #[must_use]
    pub fn find(&self, local: &str) -> Option<&Element> {
        if self.local() == local {
            return Some(self);
        }
        self.elements().find_map(|child| child.find(local))
    }

    /// The concatenated text directly inside this element.
    #[must_use]
    pub fn text(&self) -> String {
        self.children
            .iter()
            .filter_map(|child| match child {
                Node::Text(text) => Some(text.as_str()),
                Node::Element(_) => None,
            })
            .collect()
    }

    /// Remove the first descendant element for which `predicate` holds; the
    /// enveloped-signature transform removes the `Signature`.
    pub fn remove_first(&mut self, predicate: &impl Fn(&Element) -> bool) -> bool {
        if let Some(index) = self
            .children
            .iter()
            .position(|child| matches!(child, Node::Element(element) if predicate(element)))
        {
            self.children.remove(index);
            return true;
        }
        self.children.iter_mut().any(|child| match child {
            Node::Element(element) => element.remove_first(predicate),
            Node::Text(_) => false,
        })
    }
}

struct Reader<'a> {
    rest: &'a str,
}

impl Reader<'_> {
    fn skip_prolog(&mut self) -> Result<(), AuthenticateError> {
        self.rest = self.rest.trim_start();
        if self.rest.starts_with("<?xml") {
            let end = self
                .rest
                .find("?>")
                .ok_or_else(|| AuthenticateError::new("the XML declaration is not closed"))?;
            self.rest = &self.rest[end + 2..];
        }
        self.skip_trivia()
    }

    /// Whitespace and comments between markup.
    fn skip_trivia(&mut self) -> Result<(), AuthenticateError> {
        loop {
            self.rest = self.rest.trim_start();
            if self.rest.starts_with("<!--") {
                let end = self
                    .rest
                    .find("-->")
                    .ok_or_else(|| AuthenticateError::new("an XML comment is not closed"))?;
                self.rest = &self.rest[end + 3..];
            } else if self.rest.starts_with("<!") || self.rest.starts_with("<?") {
                return Err(AuthenticateError::new(
                    "the XML holds a DTD or processing instruction, which this reader refuses",
                ));
            } else {
                return Ok(());
            }
        }
    }

    fn element(&mut self) -> Result<Element, AuthenticateError> {
        if !self.rest.starts_with('<') {
            return Err(AuthenticateError::new("expected an XML element"));
        }
        self.rest = &self.rest[1..];
        let name = self.take_name()?;
        let (namespaces, attributes) = self.attributes()?;

        self.rest = self.rest.trim_start();
        if let Some(rest) = self.rest.strip_prefix("/>") {
            self.rest = rest;
            return Ok(Element {
                name,
                namespaces,
                attributes,
                children: Vec::new(),
            });
        }
        self.rest = self
            .rest
            .strip_prefix('>')
            .ok_or_else(|| AuthenticateError::new("an XML start tag is not closed"))?;

        let children = self.children(&name)?;
        Ok(Element {
            name,
            namespaces,
            attributes,
            children,
        })
    }

    fn children(&mut self, name: &str) -> Result<Vec<Node>, AuthenticateError> {
        let mut children = Vec::new();
        loop {
            if self.rest.starts_with("<!--") {
                self.skip_trivia()?;
                continue;
            }
            let close = format!("</{name}");
            if let Some(rest) = self.rest.strip_prefix(&close) {
                let rest = rest.trim_start();
                self.rest = rest
                    .strip_prefix('>')
                    .ok_or_else(|| AuthenticateError::new("an XML end tag is not closed"))?;
                return Ok(children);
            }
            if self.rest.starts_with("<![CDATA[") {
                return Err(AuthenticateError::new(
                    "the XML holds a CDATA section, which this reader refuses",
                ));
            }
            if self.rest.starts_with('<') {
                children.push(Node::Element(self.element()?));
            } else if let Some(at) = self.rest.find('<') {
                let (text, rest) = self.rest.split_at(at);
                children.push(Node::Text(unescape(text)?));
                self.rest = rest;
            } else {
                return Err(AuthenticateError::new("an XML element is not closed"));
            }
        }
    }

    fn attributes(&mut self) -> Result<(Pairs, Pairs), AuthenticateError> {
        let mut namespaces = Vec::new();
        let mut attributes = Vec::new();
        loop {
            self.rest = self.rest.trim_start();
            if self.rest.starts_with('>') || self.rest.starts_with("/>") {
                return Ok((namespaces, attributes));
            }
            let name = self.take_name()?;
            self.rest = self
                .rest
                .trim_start()
                .strip_prefix('=')
                .ok_or_else(|| AuthenticateError::new("an XML attribute has no value"))?
                .trim_start();
            let quote = self
                .rest
                .chars()
                .next()
                .filter(|character| *character == '"' || *character == '\'')
                .ok_or_else(|| AuthenticateError::new("an XML attribute value is not quoted"))?;
            self.rest = &self.rest[1..];
            let end = self
                .rest
                .find(quote)
                .ok_or_else(|| AuthenticateError::new("an XML attribute value is not closed"))?;
            let value = unescape(&self.rest[..end])?;
            self.rest = &self.rest[end + 1..];

            if name == "xmlns" {
                namespaces.push((String::new(), value));
            } else if let Some(prefix) = name.strip_prefix("xmlns:") {
                namespaces.push((prefix.to_string(), value));
            } else {
                attributes.push((name, value));
            }
        }
    }

    fn take_name(&mut self) -> Result<String, AuthenticateError> {
        let end = self
            .rest
            .find(|character: char| {
                character.is_whitespace()
                    || character == '>'
                    || character == '/'
                    || character == '='
            })
            .ok_or_else(|| AuthenticateError::new("an XML name does not end"))?;
        let (name, rest) = self.rest.split_at(end);
        self.rest = rest;
        if name.is_empty() {
            return Err(AuthenticateError::new("an XML name is empty"));
        }
        Ok(name.to_string())
    }
}

/// Unescape the five predefined entities and numeric character references.
fn unescape(text: &str) -> Result<String, AuthenticateError> {
    if !text.contains('&') {
        return Ok(text.to_string());
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let end = after
            .find(';')
            .ok_or_else(|| AuthenticateError::new("an XML entity is not terminated"))?;
        let entity = &after[..end];
        let character = match entity {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            hex if hex.starts_with("#x") || hex.starts_with("#X") => {
                u32::from_str_radix(&hex[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
                    .ok_or_else(|| {
                        AuthenticateError::new("an XML character reference is not a character")
                    })?
            }
            decimal if decimal.starts_with('#') => decimal[1..]
                .parse::<u32>()
                .ok()
                .and_then(char::from_u32)
                .ok_or_else(|| {
                    AuthenticateError::new("an XML character reference is not a character")
                })?,
            other => {
                return Err(AuthenticateError::new(format!(
                    "the XML holds the entity '&{other};', which this reader does not define"
                )));
            }
        };
        out.push(character);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_element_is_parsed_with_its_namespaces_attributes_and_text() {
        let element = Element::parse(
            r#"<?xml version="1.0"?><saml:Assertion xmlns:saml="urn:s" ID="_1"><!-- c -->
               <saml:Issuer>idp</saml:Issuer></saml:Assertion>"#,
        )
        .expect("parsed");

        assert_eq!(element.local(), "Assertion");
        assert_eq!(element.prefix(), "saml");
        assert_eq!(element.attribute("ID"), Some("_1"));
        assert_eq!(element.find("Issuer").expect("issuer").text(), "idp");
    }

    #[test]
    fn a_cdata_section_is_refused_rather_than_read_wrong() {
        let failure = Element::parse("<a><![CDATA[x]]></a>").expect_err("refused");

        assert!(failure.message.contains("CDATA"));
    }

    #[test]
    fn removing_the_signature_leaves_the_rest_of_the_assertion() {
        let mut element =
            Element::parse(r#"<A xmlns="u"><Signature>s</Signature><Subject>who</Subject></A>"#)
                .expect("parsed");

        let removed = element.remove_first(&|child| child.local() == "Signature");

        assert!(removed);
        assert_eq!(
            element.canonical(&[]),
            r#"<A xmlns="u"><Subject>who</Subject></A>"#
        );
    }
}
