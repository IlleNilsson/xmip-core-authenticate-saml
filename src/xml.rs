//! A signed assertion as an element tree, read through the estate's one
//! XML reader, and the exclusive canonicalization it needs.
//!
//! The text is read by `codec::xml::tree`, the reader every XML in the
//! estate goes through: elements, attributes, the namespaces each element
//! declares, and text with line ends and an attribute's white space made
//! what XML 1.0 makes them and the five predefined entities and character
//! references read. Comments are passed over, as exclusive canonicalization
//! without comments does. CDATA sections, processing instructions and a
//! document type declaration are refused rather than read, and so is
//! nesting past [`DEEPEST`], because a signature over something read wrong
//! is worse than a refusal. Until 2026-11-13 this file was a reader of its
//! own.
//!
//! [`Element::canonical`] renders exclusive XML canonicalization (XML-EXC-C14N
//! 1.0) for the common case: no comments, no `InclusiveNamespaces` prefix
//! list, namespace declarations emitted where visibly used and not already
//! rendered by an ancestor, attributes ordered by namespace then local name,
//! text and attribute values escaped as the specification says. It does not
//! implement the `xml:` attribute inheritance rule; an assertion needing it
//! does not verify, and [`crate`]'s documentation says so.

use authenticate::AuthenticateError;
use codec::xml::tree::{self, Document, Options};

/// One element of the tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Element {
    /// The qualified name, `saml:Assertion` or `Assertion`.
    pub name: String,
    /// The `xmlns` and `xmlns:*` declarations on this element, prefix then
    /// URI; the default namespace is the empty prefix.
    pub namespaces: Vec<(String, String)>,
    /// The other attributes, qualified name then value as read.
    pub attributes: Vec<(String, String)>,
    /// The element's children in order.
    pub children: Vec<Node>,
}

/// A child: an element or a run of text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Node {
    /// A nested element.
    Element(Element),
    /// Character data, as read.
    Text(String),
}

impl Element {
    /// Parse one document into its root element.
    ///
    /// # Errors
    ///
    /// Where the text is not one well-formed document, or holds what this
    /// gate refuses.
    pub fn parse(xml: &str) -> Result<Self, AuthenticateError> {
        let options = Options {
            depth: DEEPEST,
            cdata: false,
            instructions: false,
        };
        let document = Document::parse_with(xml, &options)
            .map_err(|refused| AuthenticateError::new(refused.to_string()))?;
        Ok(Self::of(document.root_element()))
    }

    /// The element `node` is, and everything inside it but comments.
    fn of(node: tree::Node<'_>) -> Self {
        let pair = |(name, value): (&str, &str)| (name.to_string(), value.to_string());
        Self {
            name: node.name().to_string(),
            namespaces: node.declarations().map(pair).collect(),
            attributes: node
                .attributes()
                .map(|attribute| pair((attribute.name(), attribute.value())))
                .collect(),
            children: node
                .children()
                .filter_map(|child| {
                    if child.is_element() {
                        Some(Node::Element(Self::of(child)))
                    } else {
                        child
                            .text()
                            .filter(|_| child.is_text())
                            .map(|text| Node::Text(text.to_string()))
                    }
                })
                .collect(),
        }
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

    /// The first child element with this local name. A child and never a
    /// deeper descendant: what a signed assertion says is read from where
    /// the schema puts it, so nothing planted lower down — inside the
    /// unsigned `Signature`, or an `Advice` — is read in its place.
    #[must_use]
    pub fn child(&self, local: &str) -> Option<&Element> {
        self.elements().find(|element| element.local() == local)
    }

    /// Every child element with this local name, in order.
    pub fn children_named<'a>(&'a self, local: &'a str) -> impl Iterator<Item = &'a Element> {
        self.elements()
            .filter(move |element| element.local() == local)
    }

    /// The child elements along `path`, each a child of the one before:
    /// `["Subject", "NameID"]`.
    #[must_use]
    pub fn at(&self, path: &[&str]) -> Option<&Element> {
        path.iter()
            .try_fold(self, |element, local| element.child(local))
    }

    /// Whether anything but whitespace stands between the child elements.
    #[must_use]
    pub fn has_text(&self) -> bool {
        self.children
            .iter()
            .any(|child| matches!(child, Node::Text(text) if !text.trim().is_empty()))
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

    /// Remove the first child element for which `predicate` holds; the
    /// enveloped-signature transform removes the assertion's own
    /// `Signature`, which is its child.
    pub fn remove_child(&mut self, predicate: &impl Fn(&Element) -> bool) -> bool {
        let Some(index) = self
            .children
            .iter()
            .position(|child| matches!(child, Node::Element(element) if predicate(element)))
        else {
            return false;
        };
        self.children.remove(index);
        true
    }
}

/// How deep elements may nest. An assertion is six deep at most; the cap
/// stops a document built to exhaust the stack before any signature is
/// checked.
pub const DEEPEST: usize = 32;

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
        assert_eq!(element.child("Issuer").expect("issuer").text(), "idp");
    }

    #[test]
    fn a_child_is_read_where_it_stands_and_never_from_deeper_down() {
        let element = Element::parse(
            "<A><Signature><Object><Subject>planted</Subject></Object></Signature>\
             <Subject><NameID>who</NameID></Subject></A>",
        )
        .expect("parsed");

        assert_eq!(
            element.at(&["Subject", "NameID"]).expect("a name").text(),
            "who"
        );
        assert_eq!(element.children_named("Subject").count(), 1);
        assert!(element.at(&["Subject", "Absent"]).is_none());
    }

    #[test]
    fn a_document_nested_past_the_cap_is_refused_before_anything_reads_it() {
        let deep = format!(
            "{}{}",
            "<a>".repeat(DEEPEST + 1),
            "</a>".repeat(DEEPEST + 1)
        );
        let held = format!("{}{}", "<a>".repeat(DEEPEST), "</a>".repeat(DEEPEST));

        let failure = Element::parse(&deep).expect_err("too deep");

        assert!(failure.message.contains("nests deeper"), "{failure}");
        assert!(Element::parse(&held).is_ok());
    }

    #[test]
    fn a_cdata_section_an_instruction_and_a_dtd_are_refused_rather_than_read_wrong() {
        let failure = Element::parse("<a><![CDATA[x]]></a>").expect_err("refused");
        assert!(failure.message.contains("CDATA"));
        let failure = Element::parse("<a><?pi x?></a>").expect_err("refused");
        assert!(failure.message.contains("processing instruction"));
        let failure = Element::parse("<!DOCTYPE a><a/>").expect_err("refused");
        assert!(failure.message.contains("DTD"));
    }

    #[test]
    fn removing_the_signature_leaves_the_rest_of_the_assertion() {
        let mut element =
            Element::parse(r#"<A xmlns="u"><Signature>s</Signature><Subject>who</Subject></A>"#)
                .expect("parsed");

        let removed = element.remove_child(&|child| child.local() == "Signature");

        assert!(removed);
        assert_eq!(
            element.canonical(&[]),
            r#"<A xmlns="u"><Subject>who</Subject></A>"#
        );
    }
}
