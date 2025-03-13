# Google Identity Platform & Keyring

## Google Identity Platform

* OpenID Connect configuration: https://accounts.google.com/.well-known/openid-configuration
* Access Token (AT): opaque, reference token
* AT is validated via the tokenifo endpoint: https://oauth2.googleapis.com/tokeninfo?access_token=[AT]
* ID token: (JWT), `azp` claim = `aud` claim => use the nonce claim
* ID token is validated using `jwks_uri`="https://www.googleapis.com/oauth2/v3/certs"

## Client

1. Web client
2. Implicit flow => no refresh token, the client is reauthenticated using cookies
3. A `login_hint` (an email address of the signing user)
4. Gets two tokens, an opaque/reference AT, and ID token of type JWT

## Data Store, the Resource Server 1 (RS1)

1. Validates AT via the tokeninfo endpoint

## Keyring, the Resource Server 2, 3, ... (RS2, RS3, ...)

1. Three modes: single user, multi user, or public encryption
2. Validates ID token using the "iss": "https://accounts.google.com" claim
3. Uses `client_id` (`azp`) constraint
4. Uses `keyring_uri` in AAD