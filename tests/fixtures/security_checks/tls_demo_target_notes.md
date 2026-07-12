# TLS Demo Target Notes

Use a test endpoint configured with TLS 1.0 or a weak cipher such as DES-CBC3-SHA to demonstrate TLS misconfiguration findings.

Expected VulNexus category: TLS misconfiguration.
Expected rules include WEAK_TLS_VERSION, WEAK_CIPHER_SUITE, NO_HSTS, or WEAK_HSTS depending on the target.
