## An implementation of the Linked Data Signatures specification for JSON-LD.
##
## Author: Christopher Allan Webber <cwebber@dustycloud.org>
##
## BSD 3-Clause License
## Copyright (c) 2017 Spec-Ops.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions are met:
##
## Redistributions of source code must retain the above copyright notice,
## this list of conditions and the following disclaimer.
##
## Redistributions in binary form must reproduce the above copyright
## notice, this list of conditions and the following disclaimer in the
## documentation and/or other materials provided with the distribution.
##
## Neither the name of the Spec-Ops nor the names of its contributors
## may be used to endorse or promote products derived from this
## software without specific prior written permission.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
## IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
## TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
## PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
## HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
## SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
## TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
## PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
## LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
## NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
## SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import base64
import copy
import json
import isodate
from datetime import datetime
from pyld import jsonld
import pytz

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

SECURITY_CONTEXT_URL = 'https://w3id.org/security/v1'
SECURITY_CONTEXT = {
    "@context": {
        "id": "@id",
        "type": "@type",

    "dc": "http://purl.org/dc/terms/",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

    "EcdsaKoblitzSignature2016": "sec:EcdsaKoblitzSignature2016",
        "EncryptedMessage": "sec:EncryptedMessage",
        "GraphSignature2012": "sec:GraphSignature2012",
        "LinkedDataSignature2015": "sec:LinkedDataSignature2015",
        "LinkedDataSignature2016": "sec:LinkedDataSignature2016",
        "CryptographicKey": "sec:Key",

    "authenticationTag": "sec:authenticationTag",
        "canonicalizationAlgorithm": "sec:canonicalizationAlgorithm",
        "cipherAlgorithm": "sec:cipherAlgorithm",
        "cipherData": "sec:cipherData",
        "cipherKey": "sec:cipherKey",
        "created": {"@id": "dc:created", "@type": "xsd:dateTime"},
        "creator": {"@id": "dc:creator", "@type": "@id"},
        "digestAlgorithm": "sec:digestAlgorithm",
        "digestValue": "sec:digestValue",
        "domain": "sec:domain",
        "encryptionKey": "sec:encryptionKey",
        "expiration": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "initializationVector": "sec:initializationVector",
        "iterationCount": "sec:iterationCount",
        "nonce": "sec:nonce",
        "normalizationAlgorithm": "sec:normalizationAlgorithm",
        "owner": {"@id": "sec:owner", "@type": "@id"},
        "password": "sec:password",
        "privateKey": {"@id": "sec:privateKey", "@type": "@id"},
        "privateKeyPem": "sec:privateKeyPem",
        "publicKey": {"@id": "sec:publicKey", "@type": "@id"},
        "publicKeyPem": "sec:publicKeyPem",
        "publicKeyService": {"@id": "sec:publicKeyService", "@type": "@id"},
        "revoked": {"@id": "sec:revoked", "@type": "xsd:dateTime"},
        "salt": "sec:salt",
        "signature": "sec:signature",
        "signatureAlgorithm": "sec:signingAlgorithm",
        "signatureValue": "sec:signatureValue"}}

IDENTITY_CONTEXT_URL = 'https://w3id.org/identity/v1'
IDENTITY_CONTEXT = {
    "@context": {
        "id": "@id",
        "type": "@type",

    "cred": "https://w3id.org/credentials#",
        "dc": "http://purl.org/dc/terms/",
        "identity": "https://w3id.org/identity#",
        "perm": "https://w3id.org/permissions#",
        "ps": "https://w3id.org/payswarm#",
        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
        "sec": "https://w3id.org/security#",
        "schema": "http://schema.org/",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

    "Group": "https://www.w3.org/ns/activitystreams#Group",

    "claim": {"@id": "cred:claim", "@type": "@id"},
        "credential": {"@id": "cred:credential", "@type": "@id"},
        "issued": {"@id": "cred:issued", "@type": "xsd:dateTime"},
        "issuer": {"@id": "cred:issuer", "@type": "@id"},
        "recipient": {"@id": "cred:recipient", "@type": "@id"},
        "Credential": "cred:Credential",
        "CryptographicKeyCredential": "cred:CryptographicKeyCredential",

    "about": {"@id": "schema:about", "@type": "@id"},
        "address": {"@id": "schema:address", "@type": "@id"},
        "addressCountry": "schema:addressCountry",
        "addressLocality": "schema:addressLocality",
        "addressRegion": "schema:addressRegion",
        "comment": "rdfs:comment",
        "created": {"@id": "dc:created", "@type": "xsd:dateTime"},
        "creator": {"@id": "dc:creator", "@type": "@id"},
        "description": "schema:description",
        "email": "schema:email",
        "familyName": "schema:familyName",
        "givenName": "schema:givenName",
        "image": {"@id": "schema:image", "@type": "@id"},
        "label": "rdfs:label",
        "name": "schema:name",
        "postalCode": "schema:postalCode",
        "streetAddress": "schema:streetAddress",
        "title": "dc:title",
        "url": {"@id": "schema:url", "@type": "@id"},
        "Person": "schema:Person",
        "PostalAddress": "schema:PostalAddress",
        "Organization": "schema:Organization",

    "identityService": {"@id": "identity:identityService", "@type": "@id"},
        "idp": {"@id": "identity:idp", "@type": "@id"},
        "Identity": "identity:Identity",

    "paymentProcessor": "ps:processor",
        "preferences": {"@id": "ps:preferences", "@type": "@vocab"},

    "cipherAlgorithm": "sec:cipherAlgorithm",
        "cipherData": "sec:cipherData",
        "cipherKey": "sec:cipherKey",
        "digestAlgorithm": "sec:digestAlgorithm",
        "digestValue": "sec:digestValue",
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "initializationVector": "sec:initializationVector",
        "member": {"@id": "schema:member", "@type": "@id"},
        "memberOf": {"@id": "schema:memberOf", "@type": "@id"},
        "nonce": "sec:nonce",
        "normalizationAlgorithm": "sec:normalizationAlgorithm",
        "owner": {"@id": "sec:owner", "@type": "@id"},
        "password": "sec:password",
        "privateKey": {"@id": "sec:privateKey", "@type": "@id"},
        "privateKeyPem": "sec:privateKeyPem",
        "publicKey": {"@id": "sec:publicKey", "@type": "@id"},
        "publicKeyPem": "sec:publicKeyPem",
        "publicKeyService": {"@id": "sec:publicKeyService", "@type": "@id"},
        "revoked": {"@id": "sec:revoked", "@type": "xsd:dateTime"},
        "signature": "sec:signature",
        "signatureAlgorithm": "sec:signatureAlgorithm",
        "signatureValue": "sec:signatureValue",
        "CryptographicKey": "sec:Key",
        "EncryptedMessage": "sec:EncryptedMessage",
        "GraphSignature2012": "sec:GraphSignature2012",
        "LinkedDataSignature2015": "sec:LinkedDataSignature2015",

    "accessControl": {"@id": "perm:accessControl", "@type": "@id"},
        "writePermission": {"@id": "perm:writePermission", "@type": "@id"}
    }
}
    

_get_values = jsonld.JsonLdProcessor.get_values
def _get_value(obj, key):
    try:
        return _get_values(obj, key)[0]
    # A bit more accurate since we're trying to pull a value out of a specific
    # key, and nothing exists for this one
    except IndexError:
        raise KeyError(key)
_has_value = jsonld.JsonLdProcessor.has_value


def _make_simple_loader(url_map, load_unknown_urls=True,
                        cache_externally_loaded=True):
    def _make_context(url, doc):
        return {
            "contextUrl": None,
            "documentUrl": url,
            "document": doc}

    # Wrap in the structure that's expected to come back from the
    # documentLoader
    _pre_url_map = {}
    _pre_url_map.update(url_map)
    _url_map = {
        url: _make_context(url, doc)
        for url, doc in _pre_url_map.items()}

    def loader(url):
        if url in _url_map:
            return _url_map[url]
        elif load_unknown_urls:
            doc = jsonld.load_document(url)
            # @@: Is this optimization safe in all cases?
            if isinstance(doc["document"], str):
                doc["document"] = json.loads(doc["document"])
            _url_map[url] = doc
            return doc
        else:
            raise jsonld.JsonLdError(
                "url not found and loader set to not load unknown URLs.",
                {'url': url})

    return loader

_security_context_loader = _make_simple_loader(
    {SECURITY_CONTEXT_URL: SECURITY_CONTEXT,
     IDENTITY_CONTEXT_URL: IDENTITY_CONTEXT})

# @@: Shouldn't this be a mapping from these names to their actual
#   functionality?  Seems kludgy to have all these if-elif-else things
#   as interspersed through the document...
#   Okay, answer is yes

# TODO: Make these JsonLdErrors
# class LdsError(jsonld.JsonLdError): pass
# class LdsTypeError(LdsError, TypeError): pass
class LdsError(Exception): pass
class LdsTypeError(LdsError, TypeError): pass

def is_valid_uri(obj):
    """
    Check to see if OBJ is a valid URI

    (or at least do the best check we can: that it's a string, and that
    it contains the ':' character.)
    """
    return isinstance(obj, str) and ":" in obj

def sign(document, options):
    """
    Signs a JSON-LD document using a digital signature.

     - input: the JSON-LD document to be signed.
     - options: options to use:
        [privateKeyPem] A PEM-encoded private key.
        [creator] the URL to the paired public key.
        [date] an optional date to override the signature date with.
               If provided, must have an "aware" timezone
               (.tzinfo not None)
        [domain] an optional domain to include in the signature.
        [nonce] an optional nonce to include in the signature.
        [algorithm] the algorithm to use, eg: 'GraphSignature2012',
          'LinkedDataSignature2015' (default: 'GraphSignature2012').
    """
    options = copy.deepcopy(options)

    # TODO: The spec says privateKey, but in jsonld-signatures.js there are
    #   these two separate fields...
    options["date"] = options.get("date") or datetime.now(pytz.utc)
    options.setdefault("algorithm", "GraphSignature2012")

    if not options["algorithm"] in SUITES:
        raise LdsError(
            ("[jsig.sign] Unsupported algorithm '%s'; options.algorithm must "
             "be one of: %s") % (options["algorithm"], SUITES.keys()))

    suite = SUITES[options["algorithm"]]
    options = suite.signature_munge_verify_options(options)

    # @@: Do we need this in the sign thing?
    sig_options = {
        "date": options["date"]
    }
    if "nonce" in options:
        sig_options["nonce"] = options["nonce"]
    if "domain" in options:
        sig_options["domain"] = options["domain"]
    formatted = suite.format_for_signature(document, sig_options, options)
    sig_val = suite.sign_formatted(formatted, options)

    signature = {
        "@context": SECURITY_CONTEXT_URL,
        "type": options["algorithm"],
        "creator": options["creator"],
        "created": options["date"],
        "signatureValue": sig_val}
    if "domain" in options:
        signature["domain"] = options["domain"]
    if "nonce" in options:
        signature["nonce"] = options["nonce"]
    ctx = _get_values(document, "@context")
    compacted = jsonld.compact(
        {"https://w3id.org/security#signature": signature},
        ctx, options={
            "documentLoader": _security_context_loader})

    del compacted["@context"]
        
    output = copy.deepcopy(document)
    # @@: Wow, this seems like a terribly kludgy way to get that key,
    #   but that's what's done in jsonld-signatures.js.  I mean,
    #   I guess it should work.  I guess this is to avoid that the name may
    #   be either expanded or compacted at this point
    signature_key = list(compacted.keys())[0]
    # TODO: support multiple signatures.
    #   Same warning as in jsonld-signatures.js! ;P
    #   We could put this in the suite option?
    output[signature_key] = compacted[signature_key]
    return output


def _basic_rsa_signature(formatted, options):
    private_key = serialization.load_pem_private_key(
        options["privateKeyPem"],
        password=None,
        backend=default_backend())
    signed = private_key.sign(
        formatted,
        # I'm guessing this is the right padding function...?
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    return base64.b64encode(signed).decode("utf-8")


def _getDataToHash_2012_2015(input, sig_options, options):
    # TODO: These are two separate algorithms, so we should separate them
    to_hash = ""
    if options["algorithm"] == "GraphSignature2012":
        if "nonce" in sig_options:
            to_hash += sig_options["nonce"]
        to_hash += sig_options["date"]
        to_hash += input
        if "domain" in sig_options:
            to_hash += "@" + sig_options["domain"]
    else:
        headers = {
            "http://purl.org/dc/elements/1.1/created": sig_options.get("date"),
            "https://w3id.org/security#domain": sig_options.get("domain"),
            "https://w3id.org/security#nonce": sig_options.get("nonce")};
        # add headers in lexicographical order
        for key in sorted(headers.keys()):
            value = headers[key]
            if value is not None:
                to_hash += "%s: %s\n" % (key, value)
        to_hash += input
    return to_hash.encode("utf-8")


def _w3c_date(dt):
    # We may need to convert it to UTC
    if dt.tzinfo is not pytz.utc:
        dt = dt.astimezone(pytz.utc)

    return isodate.datetime_isoformat(dt)


# Verification

def verify(signed_document, options):
    """
    Signs a JSON-LD document using a digital signature.

    Args:
     - input: the JSON-LD document to be verified.
     - options:

    # TODO: Not all these are implemented yet, and some may be algorithm
    #   specific
    Options:
     - publicKey(signature, options): A procedure which, if present, is called
       to retrieve the public key.  Must do all validation that ownership
       correcly aligns.
     - checkNonce(nonce, options)] a procedure to check if the nonce (null
       if none) used in the signature is valid.
     - checkDomain(domain, options): a procedure to check if the domain used
       (null if none) is valid.
     - checkKey(key, options): a procedure to check if the key used to sign the
       message is trusted.
     - checkKeyOwner(owner, key, options): a procedure to check if the key's
       owner is trusted.
     - checkTimestamp: check signature timestamp (default: false).
     - maxTimestampDelta: signature must be created within a window of
       this many seconds (default: 15 minutes).
     - documentLoader(url): the document loader.
     - id the ID (full URL) of the node to check the signature of, if
       the input contains multiple signed nodes.
    """
    loader = options.get("documentLoader", _security_context_loader)

    # Here's a TODO copy-pasta'ed from jsonld-signatures.js:
    #   TODO: frame before getting signature, not just compact? considerations:
    #   should the assumption be that the signature is on the top-level object
    #   and thus framing is unnecessary?
    compacted = jsonld.compact(
        signed_document, SECURITY_CONTEXT_URL, options={
            "documentLoader": loader})

    try:
        signature = _get_values(compacted, "signature")[0]
    except IndexError:
        raise LdsError('[jsigs.verify] No signature found.')

    try:
        suite_name = _get_values(signature, "type")[0]
    except IndexError:
        suite_name = ""

    if not suite_name in SUITES:
        raise LdsError(
            ("[jsigs.verify] Unsupported signature algorithm \"%s\"; "
             "supported algorithms are: %s") % (suite_name,
                                                SUITES.keys()))
    suite = SUITES[suite_name]

    # TODO: Should we be framing here?  According to my talks with Dave Longley
    #   we probably should, though I don't know how well pyld supports framing
    #   and I need to wrap my head around it better
    # @@: So here we have to extract the signature

    # @@: 3 before 1 and 2?  Well we need it in 1 and 2 :P
    # SPEC (3): Remove any signature nodes from the default graph in
    #   document and save it as signature.
    # @@: This isn't recursive, should it be?  Also it just handles
    #   one value for now.
    signature = compacted.pop("signature")

    # SPEC (1): Get the public key by dereferencing its URL identifier
    #   in the signature node of the default graph of signed document.
    # @@: Rest of SPEC(1) in _get_public_key
    get_public_key = options.get("publicKey", _get_public_key)
    public_key = get_public_key(signature, options)

    # SPEC (2): Let document be a copy of signed document. 
    document = copy.deepcopy(signed_document)

    # SPEC (5): Create a value tbv that represents the data to be
    #   verified, and set it to the result of running the Create Verify
    #   Hash Algorithm, passing the information in signature.
    # TODO: This doesn't look like the same verification step
    #   being done in the signature step as ported from jsonld-signatures.js
    #   It looks like what step we do here should be farmed out depending
    #   on the signature suite used.
    # @@: Maybe sig_options should be munged by the suite?
    sig_options = {}
    if "publicKeyPem" in public_key:
        sig_options["publicKeyPem"] = _get_value(public_key, "publicKeyPem")
    if "publicKeyWif" in public_key:
        sig_options["publicKeyWif"] = _get_value(public_key, "publicKeyWif")
    if "nonce" in signature:
        sig_options["nonce"] = _get_value(signature, "nonce")
    # @@: Why isn't this also "created"?
    if "created" in signature:
        sig_options["nonce"] = _get_value(signature, "created")
    if "domain" in signature:
        sig_options["domain"] = _get_value(signature, "domain")

    tbv = suite.format_for_signature(document, sig_options, options)

    # SPEC (6): Pass the signatureValue, tbv, and the public key to
    #   the signature algorithm (e.g. JSON Web Signature using
    #   RSASSA-PKCS1-v1_5 algorithm). Return the resulting boolean
    #   value.
    return suite.verify_signature(signature, tbv, public_key, options)


def _get_public_key(signature, options):
    if not "creator" in signature:
        raise LdsError(
            '[jsigs.verify] creator not found on signature.')
    creator = _get_security_compacted_jsonld(_get_value(signature, "creator"),
                                             options)
    if not "publicKey" in creator:
        raise LdsError(
            '[jsigs.verify] publicKey not found on creator object')

    # @@: What if it's a fragment identifier on an embedded object?
    public_key = _get_security_compacted_jsonld(
        _get_value(creator, "publicKeyPem"), options)
    public_key_id = public_key.get("@id") or public_key.get("id")

    owners = _get_values(public_key, "owner")
    owner = None
    for maybe_owner in owners:
        if _has_value(maybe_owner, "publicKey", public_key_id):
            owner = maybe_owner
            break

    # SPEC (1): Confirm that the linked data document that describes
    #   the public key specifies its owner and that its owner's URL
    #   identifier can be dereferenced to reveal a bi-directional link
    #   back to the key.
    if not owner:
        raise LdsError(
            '[jsigs.verify] The public key is not owned by its declared owner.')

    # SPEC (1): Ensure that the key's owner is a trusted entity before
    # proceeding to the next step.
    check_key_owner = options.get("checkKeyOwner")
    if check_key_owner and not check_key_owner(signature, public_key, options):
        raise LdsError(
            '[jsigs.verify] The owner of the public key is not trusted.')

    return public_key


def _security_compact(document, options):
    loader = options.get("documentLoader", _security_context_loader)
    return jsonld.compact(document, SECURITY_CONTEXT_URL,
                          options={"documentLoader": loader})

def _get_jsonld(id, options):
    if isinstance(id, dict):
        id = id.get("id") or id.get("@id")
        if not id:
            raise ValueError("Tried to fetch object with no id: %s" % id)
    loader = options.get("documentLoader", _security_context_loader)
    return loader(id)["document"]

def _get_security_compacted_jsonld(id, options):
    return _security_compact(_get_jsonld(id, options), options)


# TODO: Are we actually passing in multiple aglgorithms for message
#   canonicalization *and* message digest?
def create_verify_hash(document, suite, options,
                       options_to_canonicalize):
    """
    
    """
    normalized_input = suite.normalize_jsonld(document, options)

    # SPEC (1): Let options be a copy of input options.
    options_to_canonicalize = copy.deepcopy(options_to_canonicalize)

    # SPEC (2): If type, id, or signatureValue exists in options,
    #   remove the entry.
    # @@: Well since we're specifically passing these in to this procedure
    #   I guess we don't need to do that...

    # SPEC (3): If created does not exist in options, add an entry
    #   with a value that is an ISO8601 combined date and time string
    #   containing the current date and time accurate to at least one
    #   second, in Universal Time Code format. For example:
    #   2017-11-13T20:21:34Z.
    if not "created" in options_to_canonicalize:
        options_to_canonicalize["created"] = _w3c_date(datetime.now(pytz.utc))

    # SPEC (4): Generate output by: 
    # SPEC (4.1): Creating a canonicalized options document by
    #   canonicalizing options according to the canonicalization
    #   algorithm (e.g. the GCA2015 [RDF-DATASET-NORMALIZATION]
    #   algorithm). 
    # Well, we need to add the context first:
    options_to_canonicalize["@context"] = SECURITY_CONTEXT_URL
    canonical_options = suite.normalize_jsonld(
        options_to_canonicalize, options)

    # SPEC (4.2): Hash canonicalized options document using the
    #   message digest algorithm (e.g. SHA-256) and set output to the
    #   result.
    output = suite.message_digest(canonical_options, options)

    # SPEC (4.3): Hash canonicalized document using the message digest
    #   algorithm (e.g. SHA-256) and append it to output.
    output += suite.message_digest(normalized_input, options)

    # SPEC (5): Hash output using the message digest algorithm
    #   (e.g. SHA-256) and replace it with the result.
    output = suite.message_digest(output, options)

    # SPEC (6): Return output. 
    return output

def _rsa_verify_sig(sig_value, formatted, public_key_jsonld):
    """
     - sig_value: data to be verified
     - public_key: creator of this document's public_key 
     - tbv: to be verified
    """
    # TODO: Support other formats than just PEM
    public_key = serialization.load_pem_public_key(
        _get_value(public_key_jsonld, "publicKeyPem").decode("utf-8"),
        backend=default_backend())

    try:
        public_key.verify(
            base64.b64decode(sig_value.encode("utf-8")), formatted,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# In the future, we'll be doing a lot more work based on what suite is
# selected.

def signature_common_munge_verify(options):
    if not is_valid_uri(options["creator"]):
        raise LdsTypeError(
            "[jsig.sign] options.creator must be a URL string.")

    if "domain" in options and not is_valid_uri(options["domain"]):
        raise LdsTypeError(
            "[jsig.sign] options.domain must be a string.")

    if "nonce" in options and not is_valid_uri(options["nonce"]):
        raise LdsTypeError(
            "[jsig.sign] options.nonce must be a string.")

    if not isinstance(options["date"], str):
        options["date"] = _w3c_date(options["date"])

    return options

class SignatureSuite():
    name = None

    @classmethod
    def signature_munge_verify_options(cls, options):
        options = signature_common_munge_verify(options)
        return options

    @classmethod
    def normalize_jsonld(cls, document, options):
        raise NotImplementedError()

    @classmethod
    def format_for_signature(cls, document, sig_options, options):
        raise NotImplementedError()

    @classmethod
    def sign_formatted(cls, formatted, options):
        raise NotImplementedError()

    @classmethod
    def verify_formatted(cls, formatted, options):
        raise NotImplementedError()


def _format_gs_2012_ld_2015(suite, document, sig_options, options):
    normalized = suite.normalize_jsonld(document, options)

    if len(normalized) == 0:
        raise LdsError(
            ('[jsig.sign] '
             'The data to sign is empty. This error may be because a '
             '"@context" was not supplied in the input thereby causing '
             'any terms or prefixes to be undefined. '
             'Input: %s') % (json.dumps(document)))
    return _getDataToHash_2012_2015(normalized, sig_options, options)


class GraphSignature2012(SignatureSuite):
    name = "GraphSignature2012"

    @classmethod
    def format_for_signature(cls, document, sig_options, options):
        return _format_gs_2012_ld_2015(cls, document, sig_options, options)

    @classmethod
    def normalize_jsonld(self, document, options):
        return jsonld.normalize(
            document, {"algorithm": "URGNA2012",
                       "format": "application/nquads"})
    @classmethod
    def sign_formatted(cls, formatted, options):
        return _basic_rsa_signature(formatted, options)

    @classmethod
    def verify_formatted(cls, signature, formatted, public_key_jsonld, options):
        return _rsa_verify_sig(
            _get_value(signature, "signatureValue"),
            formatted, public_key_jsonld)


class LinkedDataSignature2015(SignatureSuite):
    name = "LinkedDataSignature2015"

    @classmethod
    def normalize_jsonld(cls, document, options):
        return jsonld.normalize(
            document, {"algorithm": "URDNA2015",
                       "format": "application/nquads"})

    @classmethod
    def format_for_signature(cls, document, sig_options, options):
        return _format_gs_2012_ld_2015(cls, document, sig_options, options)

    @classmethod
    def sign_formatted(cls, formatted, options):
        return _basic_rsa_signature(formatted, options)


class EcdsaKoblitzSignature2016(SignatureSuite):
    name = "EcdsaKoblitzSignature2016"

    @classmethod
    def signature_munge_verify_options(cls, options):
        options = signature_common_munge_verify(options)

        if not isinstance(options.get("privateKeyWif", str)):
            raise LdsTypeError(
                "[jsig.sign] options.privateKeyWif must be a base 58 "
                "formatted string.")
        elif not isinstance(options.get("privateKeyPem"), str):
            raise LdsTypeError(
                "[jsig.sign] options.privateKeyPem must be a PEM "
                "formatted string.")

        return options

class LinkedDataSignature2016(SignatureSuite):
    name = "LinkedDataSignature2016"
    



SUITES = {
    s.name: s
    for s in [GraphSignature2012,
              LinkedDataSignature2015,
              # EcdsaKoblitzSignature2016,
              ]}

