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
    {SECURITY_CONTEXT_URL: SECURITY_CONTEXT})

# @@: Shouldn't this be a mapping from these names to their actual
#   functionality?  Seems kludgy to have all these if-elif-else things
#   as interspersed through the document...
#   Okay, answer is yes
class LdsError(jsonld.JsonLdError): pass
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
    # TODO: The spec says privateKey, but in jsonld-signatures.js there are
    #   these two separate fields...
    options["date"] = options.get("date") or datetime.now(pytz.utc)
    options.setdefault("algorithm", "GraphSignature2012")

    if not options["algorithm"] in SUPPORTED_ALGORITHMS:
        raise LdsError(
            ("[jsig.sign] Unsupported algorithm '%s'; options.algorithm must "
             "be one of: %s") % (options["algorithm"], SUPPORTED_ALGORITHMS))

    # @@: Why not move this into the signature algorithm tooling itself?
    if (options["algorithm"] == "EcdsaKoblitzSignature2016"):
        if not isinstance(options.get("privateKeyWif", str)):
            raise LdsTypeError(
                "[jsig.sign] options.privateKeyWif must be a base 58 "
                "formatted string.")
        elif not isinstance(options.get("privateKeyPem"), str):
            raise LdsTypeError(
                "[jsig.sign] options.privateKeyPem must be a PEM "
                "formatted string.")

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

    if options["algorithm"] == "GraphSignature2012":
        normalize_algorithm = "URGNA2012"
    else:
        normalize_algorithm = "URDNA2015"

    normalized = jsonld.normalize(
        document, {"algorithm": normalize_algorithm,
                   "format": "application/nquads"})
    if len(normalized) == 0:
        raise LdsError(
            ('[jsig.sign] '
             'The data to sign is empty. This error may be because a '
             '"@context" was not supplied in the input thereby causing '
             'any terms or prefixes to be undefined. '
             'Input: %s') % (json.dumps(document)))

    sig_val = _create_signature(
        normalized, options)
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
    ctx = jsonld.JsonLdProcessor.get_values(document, "@context")
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
    output[signature_key] = compacted[signature_key]
    return output

    
def _create_signature(normalized, options):
    # TODO: Support bitcoin based signature
    # if options.algorithm == 'EcdsaKoblitzSignature2016':
    #     ...
    private_key = serialization.load_pem_private_key(
        options["privateKeyPem"],
        password=None,
        backend=default_backend())
    signed = private_key.sign(
        _getDataToHash_2012_2015(normalized, options),
        # I'm guessing this is the right padding function...?
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    return base64.b64encode(signed).decode("utf-8")


def _getDataToHash_2012_2015(input, options):
    # @@: This is the old algorithm and does not reflect the 2017
    #   algorithm document.  We should split this out...
    to_hash = ""
    if options["algorithm"] == "GraphSignature2012":
        if "nonce" in options:
            to_hash += options["nonce"]
        to_hash += options["date"]
        to_hash += input
        if "domain" in options:
            to_hash += "@" + options["domain"]
    else:
        headers = {
            "http://purl.org/dc/elements/1.1/created": options.get("date"),
            "https://w3id.org/security#domain": options.get("domain"),
            "https://w3id.org/security#nonce": options.get("nonce")};
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


# In the future, we'll be doing a lot more work based on what algorithm is
# selected.

## We don't actually create instances of these.  Just lazily taking
## advantage of inheritance here.
def _default_option_munger(options):
    pass

class Algorithm():
    munge_verify_options = _default_option_munger
    hash_data = None
    create_signature = None

class GraphSignature2012(Algorithm):
    pass

class LinkedDataSignature2015(Algorithm):
    pass

ALGORITHMS = {
    # 'EcdsaKoblitzSignature2016': TODO,
    "GraphSignature2012": GraphSignature2012,
    "LinkedDataSignature2015": LinkedDataSignature2015,
}
SUPPORTED_ALGORITHMS = ALGORITHMS.keys()

