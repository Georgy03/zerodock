# Cryptographic interoperability fixtures

`real-nsm-cose.b64` is one complete CBOR-tagged COSE_Sign1 document emitted
by AWS Nitro NSM. It contains certificates, PCRs, a results hash, and an NSM
signature, but no AWS credentials or scan findings.

Both the Go and TypeScript verifier tests consume these exact bytes. Do not
replace it with a mock document: its purpose is to catch differences that only
appear with AWS's real multi-certificate chain and wire format.
