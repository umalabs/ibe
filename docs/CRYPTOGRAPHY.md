# Identity-Based Symmetric Key Cryptography

## Introduction

This is a set of Identity-Based Symmetric Key Cryptography Mechanisms. The client generates a content encryption key to encrypt the user's content. This key is then sent to the Resource Server for further encryption, along with the content hash and the user's ID (email address) of the individual authorized to decrypt it. The Resource Server returns the encrypted content encryption key and the corresponding metadata. To decrypt the content encryption key, the user must be authorized to access the Resource Server using an OAuth 2.0-based mechanism.

## Acronyms

* AS: Authorization Server
* RS: Resource Server

<div style="break-after:page"></div>

**Sequence Diagram for Encryption:**

```plantuml
@startuml
scale 2/3
!pragma teoz true

' --- Client ---
participant "Content Hash\nGenerator\n(HMAC-SHA-256)" as ContentHashGen
participant "Content Hash Key\nRND Generator" as ContentHashKeyRNDGen
participant "Content Encryption\n(AES-256-CTR)" as ContentEncryption
participant "Content Enc. Key\nRND Generator" as ContentEncKeyRNDGen
participant "Content IV\nRND Generator" as ContentIV_RNDGen

' --- Client Inputs ---
participant "Content\nplaintext" as ContentPlaintext
participant "User ID" as UserID

' --- Client Outputs ---
participant "Content\nciphertext" as ContentCiphertext

' --- Client-Side Generated Metadata ---
participant "Content Hash Key" as ContentHashKeyMetadata
participant "Content IV" as ContentIVMetadata

' --- RS ---
participant "HKDF" as HKDF
participant "Content Enc. Key\nEncryption\n(AES-256-GCM)" as ContentEncKeyEncryption
participant "Content nonce\nRND Generator" as ContentNonceRNDGen
participant "Identity nonce\nRND Generator" as IdentityNonceRNDGen

' --- RS Inputs ---
participant "Master Key\nTPM 2.0" as Masterkey

' --- RS-Side Generated Metadata ---
participant "Content Enc. Key\nciphertext" as ContentEncKeyCiphertextMetadata
participant "Identity\nAAD Tag" as IdentityAADTagMetadata
participant "Identity\nIV" as IdentityIVMetadata

' --- Mixed Metadata ---
participant "Identity\nAAD" as IdentityAADMetadata

box "Client"
    box "Client Data" #White
        participant ContentPlaintext
        participant ContentCiphertext
        participant UserID
    end box

    participant ContentHashGen
    participant ContentHashKeyRNDGen
    participant ContentEncryption
    participant ContentEncKeyRNDGen
    participant ContentIV_RNDGen

    box "Client-Side Generated Metadata" #LightBlue
        participant ContentHashKeyMetadata
        participant ContentIVMetadata
    end box

    box "Mixed Metadata" #LightBlue
        participant IdentityAADMetadata
    end box

    box "RS-Side Generated Metadata" #LightBlue
        participant ContentEncKeyCiphertextMetadata
        participant IdentityIVMetadata
        participant IdentityAADTagMetadata
    end box
end box

box "RS"
    participant ContentEncKeyEncryption
    participant HKDF
    participant ContentNonceRNDGen
    participant IdentityNonceRNDGen

    box "RS Data" #White
        participant Masterkey
    end box
end box

note across: The request from the Client to the RS to encrypt the Content Encryption Key should be authorized using JWT to prevent service misuse. The response includes the Identity nonce, Identity IV, Content Encryption Key ciphertext, and Identity AAD tag.
note over IdentityAADMetadata: The AAD may include additional information, typically the URL of the RS.

Masterkey -> HKDF: Master Key

' --- Content plaintext for hash generation ---
ContentPlaintext -> ContentHashGen: Content plaintext
' --- Content Hash Generation ---
ContentHashGen -> ContentHashKeyRNDGen: Get ContentHash Key
' --- Content Hash Key Generation process ---
activate ContentHashKeyRNDGen
ContentHashKeyRNDGen -> ContentHashKeyRNDGen: Generate Random\nContent Hash Key
ContentHashKeyRNDGen --> ContentHashGen: Content Hash Key
deactivate ContentHashKeyRNDGen
' --- Content Hash Generation process ---
activate ContentHashGen
ContentHashKeyRNDGen --> ContentHashKeyMetadata: Content Hash Key
note right of ContentHashGen: key = Content Hash Key,\nmessage = Content plaintext
ContentHashGen -> ContentHashGen: Generate Content hash
ContentHashGen --> IdentityAADMetadata: Content hash
deactivate ContentHashGen

' Content plaintext for encryption
ContentPlaintext -> ContentEncryption: Content plaintext
' Content plaintext Encryption
ContentEncryption -> ContentEncKeyRNDGen: Get Content Enc. Key
' --- Content Encryption Key Generation process ---
activate ContentEncKeyRNDGen
ContentEncKeyRNDGen -> ContentEncKeyRNDGen: Generate Random\nContent Enc. Key
ContentEncKeyRNDGen --> ContentEncryption: Content Enc. Key
deactivate ContentEncKeyRNDGen
UserID->ContentEncKeyRNDGen: User ID (usually the email address of the individual authorized to decrypt the Content Enc. Key and,\nsubsequently, the Content ciphertext)
' --- Request for encrypting the Content Encryption Key ---
ContentEncKeyRNDGen -> ContentEncKeyEncryption: The request for encrypting the Content Encryption Key (the body of the request includes the Content Encryption Key and the User ID)
' --- Content plaintext IV Generation ---
ContentEncryption -> ContentIV_RNDGen: Get Content IV
' --- Content plaintext IV Generation process ---
activate ContentIV_RNDGen
ContentIV_RNDGen -> ContentIV_RNDGen: Generate Random\nContent IV
ContentIV_RNDGen --> ContentEncryption: Content IV
deactivate ContentIV_RNDGen
' --- Content plaintext Encryption process ---
activate ContentEncryption
ContentIV_RNDGen --> ContentIVMetadata: Content IV
ContentEncryption -> ContentEncryption: Encrypt Content
ContentEncryption --> ContentCiphertext: Content ciphertext
deactivate ContentEncryption

' --- Identity Enc. Key Generation ---
ContentEncKeyEncryption -> HKDF: Get Identity\nEncryption Key
' --- Identity nonce Generation ---
HKDF -> IdentityNonceRNDGen: Get Identity nonce
' --- Identity nonce Generation process ---
activate IdentityNonceRNDGen
IdentityNonceRNDGen -> IdentityNonceRNDGen: Generate Random\nIdentity nonce
IdentityNonceRNDGen --> HKDF: Identity nonce
deactivate IdentityNonceRNDGen
' --- Response Data ---
IdentityNonceRNDGen --> IdentityAADMetadata: Identity nonce
' --- Identity Enc. Key Generation ---
ContentEncKeyEncryption-> HKDF: User ID
' --- Identity Enc. Key Generation process ---
activate HKDF
note right of HKDF: Identity Encryption Key =\nHKDF-Expand(HKDF-Extract(Master Key, Identity nonce), User ID, key_length)
HKDF -> HKDF: Generate\nIdentity Enc. Key
HKDF --> ContentEncKeyEncryption: Identity Enc. Key
deactivate HKDF
' --- Identity IV Generation ---
ContentEncKeyEncryption -> ContentNonceRNDGen: Get Identity IV
' --- Identity IV Generation process ---
activate ContentNonceRNDGen
ContentNonceRNDGen --> ContentNonceRNDGen: Generate Random\nIdentity IV
ContentNonceRNDGen --> ContentEncKeyEncryption: Identity IV
deactivate ContentNonceRNDGen
' --- Response Data ---
ContentNonceRNDGen --> IdentityIVMetadata: Identity IV
' --- Content Key Encryption ---
IdentityAADMetadata -> ContentEncKeyEncryption: Identity AAD = Identity nonce || Content hash
' --- Content Key Encryption process ---
activate ContentEncKeyEncryption
ContentEncKeyEncryption --> ContentEncKeyEncryption: Encrypt\nContent Enc. Key
' --- Response Data ---
ContentEncKeyEncryption --> ContentEncKeyCiphertextMetadata: Content Encryption Key ciphertext
ContentEncKeyEncryption --> ContentEncKeyEncryption: Generate\nAAD Tag
' --- Response Data ---
ContentEncKeyEncryption --> IdentityAADTagMetadata: Identity\nAAD Tag
deactivate ContentEncKeyEncryption

@enduml
```

<div style="break-after:page"></div>

**Sequence Diagram for Decryption:**

```plantuml
@startuml
scale 2/3
!pragma teoz true

' --- Client ---
participant "Content Hash\nGenerator\n(HMAC-SHA-256)" as ContentHashGen
participant "Content Integrity\nVerification" as ContentIntegrityVerification
participant "Content Decryption\n(AES-256-CTR)" as ContentDecryption

' --- Client Inputs ---
participant "Content\nplaintext" as ContentPlaintext
participant "Access\nToken" as AccessToken

' --- Client Outputs ---
participant "Content\nciphertext" as ContentCiphertext

' --- Client-Side Generated Metadata ---
participant "Content Hash Key" as ContentHashKeyMetadata
participant "Content IV" as ContentIVMetadata

' --- RS ---
participant "Content Enc. Key\nDecryption\n(AES-256-GCM)" as ContentEncKeyDecryption
participant "HKDF" as HKDF
participant "Authorization\nAssessment" as AuthorizationAssessment

' --- RS Inputs ---
participant "Master Key\nTPM 2.0" as Masterkey

' --- RS-Side Generated Metadata ---
participant "Content Enc. Key\nciphertext" as ContentEncKeyCiphertextMetadata
participant "Identity\nAAD Tag" as IdentityAADTagMetadata
participant "Identity\nIV" as IdentityIVMetadata

' --- Mixed Metadata ---
participant "Identity\nAAD" as IdentityAADMetadata

box "Client"
    box "Client Data" #White
        participant ContentPlaintext
        participant ContentCiphertext
        participant AccessToken
    end box

    participant ContentHashGen
    participant ContentIntegrityVerification
    participant ContentDecryption

    box "Client-Side Generated Metadata" #LightBlue
        participant ContentHashKeyMetadata
        participant ContentIVMetadata
    end box

    box "Mixed Metadata" #LightBlue
        participant IdentityAADMetadata
    end box

    box "RS-Side Generated Metadata" #LightBlue
        participant ContentEncKeyCiphertextMetadata
        participant IdentityIVMetadata
        participant IdentityAADTagMetadata
    end box
end box

box "RS"
    participant ContentEncKeyDecryption
    participant HKDF
    participant AuthorizationAssessment

    box "RS Data" #White
        participant Masterkey
    end box
end box

note across: The request from the Client to the RS to decrypt the Content Encryption Key ciphertext must be authorized using JWT to prevent service misuse and to obtain the valid user ID. The response includes the Content Encryption Key.

Masterkey -> HKDF: Master Key

' --- Content ciphertext decryption ---
ContentCiphertext -> ContentDecryption: Content ciphertext
ContentIVMetadata -> ContentDecryption: Content IV
' --- Request for decrypting the Content Encryption Key ---
ContentDecryption -> ContentEncKeyDecryption: The request for decrypting the Content Encryption Key\n(the body of the request includes the Content Encryption Key ciphertext, Identity IV, Identity AAD, and Identity AAD Tag)
' --- Request Authorization Header
AccessToken->AuthorizationAssessment: JWT (the JWT is included in the authorization header of the request)
activate AuthorizationAssessment
' --- Content Encryption Key decryption ---
IdentityAADMetadata -> ContentEncKeyDecryption: Identity AAD
AuthorizationAssessment-> HKDF: User ID
deactivate AuthorizationAssessment
ContentEncKeyDecryption -> HKDF: Generate the Identity Enc. Key\nusing the Identity nonce\nextracted from the\nIdentity AAD
activate HKDF
note right of HKDF: Identity Encryption Key =\nHKDF-Expand(HKDF-Extract(Master Key, Identity nonce), User ID, key_length)
HKDF -> HKDF: Generate\nIdentity Enc. Key
HKDF --> ContentEncKeyDecryption: Identity Enc. Key
deactivate HKDF
ContentEncKeyCiphertextMetadata -> ContentEncKeyDecryption: Content Encryption Key ciphertext
IdentityIVMetadata -> ContentEncKeyDecryption: Identity IV
IdentityAADTagMetadata -> ContentEncKeyDecryption: Identity AAD Tag
' --- Content Encryption Key decryption process ---
activate ContentEncKeyDecryption
ContentEncKeyDecryption -> ContentEncKeyDecryption: Decrypt\nContent Enc. Key\nciphertext
ContentEncKeyDecryption --> ContentDecryption: Content Enc. Key
deactivate ContentEncKeyDecryption

' --- Content plaintext decryption process ---
activate ContentDecryption
ContentDecryption -> ContentDecryption: Decrypt Content
ContentDecryption --> ContentPlaintext: Content plaintext
deactivate ContentDecryption

ContentPlaintext -> ContentHashGen: Content plaintext
ContentHashKeyMetadata -> ContentHashGen: Content Hash Key
' --- Content Encryption Key Generation process ---
activate ContentHashGen
note right of ContentHashGen: key = Content Hash Key,\nmessage = Content plaintext
ContentHashGen -> ContentHashGen: Generate\nContent hash
ContentHashGen --> ContentIntegrityVerification: Content hash
deactivate ContentHashGen
IdentityAADMetadata -> ContentIntegrityVerification: Identity AAD = Identity nonce || Content hash
activate ContentIntegrityVerification
note right of ContentIntegrityVerification: Compare the generated Content hash with the Content hash extracted from the Identity AAD
ContentIntegrityVerification -> ContentIntegrityVerification: Compare Content hash
<-- ContentIntegrityVerification: Comparison Result
deactivate ContentIntegrityVerification

@enduml
```

The decryption process ensures that the decrypted content is indeed the original content that was encrypted for the specific user and verifies that the Resource Server processed the request correctly within the context of the intended user's identity. The authenticity of the Content hash is ensured by the AAD Tag of the AES-256-GCM function and integrity of the Content plaintext is ensured by the HMAC-SHA-256 function.

<div style="break-after:page"></div>

## OAuth 2.0/OIDC PKCE Authorization Code Grant Flow with Audience Restriction and User Email Inclusion

```plantuml
@startuml
scale 2/3
!pragma teoz true
actor User
participant "Client" as Client
participant "AS" as AS
participant "RS" as RS

== User Initiates Access ==
User -> Client: Access Application (e.g., visit website or open app)

== Authorization Request ==
Client -> User: Redirect to Authorization Server
note right: Includes parameters:\n- response_type=code\n- client_id\n- redirect_uri\n- scope (e.g., read:data openid email)\n- state\n- code_challenge\n- code_challenge_method=S256

User -> AS: Authorization Request
note right: User-Agent (Browser) sends GET request\nwith the above parameters

== User Authentication and Consent ==
AS -> User: Prompt for Authentication
User -> AS: Submit Credentials

AS -> User: Prompt for Consent
User -> AS: Grant Consent

== Authorization Response ==
AS -> User: Redirect to Client's redirect_uri\nwith authorization_code and state

== Client Receives Authorization Code ==
User -> Client: Receive Authorization Code
note right: Client verifies state parameter

== Token Request ==
Client -> AS: POST Token Request
note right: Parameters include:\n- grant_type=authorization_code\n- code\n- redirect_uri\n- client_id\n- code_verifier

== Token Response ==
AS -> Client: Token Response
note right: Returns JSON containing:\n- access_token (JWT with `aud`, `azp`, and `email` claims)\n- token_type\n- expires_in

== Access Protected Resource ==
Client -> RS: API Request with Access Token
note right: HTTP Header includes:\nAuthorization: Bearer <access_token>

== Token Validation ==
RS -> AS: (Optional) Introspect Token
note right: Or validate token signature locally if public keys are available

AS --> RS: Validation Result
note right: Valid or invalid with claims including `email`

== Provide Protected Resource ==
RS -> Client: Respond with Protected Data

@enduml
```

The sequence diagram outlines a mechanism for authenticating users and authorizing access to protected resources using the OAuth 2.0 protocol, enhanced with Proof Key for Code Exchange (PKCE). 

Key enhancements in this mechanism include the utilization of the `scope` parameter to define the `aud` (audience) claim within the Access Token, thereby restricting token validity to specific RSs. This ensures that access tokens are purpose-bound, enhancing security by preventing misuse across unintended services. Additionally, the Access Token incorporates the authenticated user's email address as an `email` claim, providing the RS with a reliable identifier for personalized access controls without necessitating additional user information requests. Further strengthening the security framework, the inclusion of the `azp` (Authorized Party) claim within the Access Token binds the token to the specific project or account service ID of the application that requested the token.

The sequence begins with the user initiating access to the client application, which redirects the user to the AS with a detailed authorization request containing parameters such as `scope`, `state`, and PKCE-related values (`code_challenge` and `code_challenge_method`). Upon successful authentication and user consent, the AS issues an Access Token. The Access Token, enriched with the `aud`, `azp`, and `email` claims, is then utilized by the client application to access protected resources from the RS. It is essential that the RS is properly configured initially to correctly evaluate these claims. The RS validates the token's integrity, audience, and extracts the user's email to manage access appropriately.

<div style="break-after:page"></div>

## Autorization and Identity-Based Symmetric Key Cryptography Mechanisms

In illustrative unrestricted mode, anyone can access the RS and encrypt content for others. However, during the decryption process, authorization is required, and a valid access token with the appropriate claims must be provided. This illustrative mode highlights a specific feature – the decoupling of the encryption initiation from immediate authorization checks at the RS.

<div style="break-after:page"></div>

## Keyring as an Authorization Server for Content Plaintext Access

In this system, the Content Encryption Key is the key to accessing the Content plaintext. Therefore, controlling access to the Content Encryption Key is effectively controlling access to the Content plaintext.

* Wrapping the Content Encryption Key can be seen as preparing the key for authorized access later. It's setting the stage for future authorization.

* Unwrapping the Content Encryption Key is granting access to the Content Encryption Key, which in turn grants access to the Content plaintext. The Keyring decides if and when to perform this unwrapping based on authorization checks.

The Keyring provides the central authorization functions and can therefore be regarded and treated as an Authorization Server. Because of this analogy, it is highly beneficial to apply the same best practices used for managing OAuth 2.0 Authorization Servers to the management of the Keyring.

**Keyring Management Best Practices (Inspired by AS Best Practices):**

* **Admin Interface (Console/Web Application):**
    * **Configuration Management:** Provide a secure admin interface (web-based or console) to configure the Keyring. This includes:
        * Master Key management (initialization, rotation, version tracking).
        * Trusted Authorization Server (AS) configurations (for JWT validation - trust anchors, JWKS endpoints, expected audiences, authorized parties).
        * Audit logging configuration.
        * Security policies and parameters.
    * **Monitoring and Logging:** Implement robust monitoring dashboards and logging capabilities within the admin interface to track Keyring health, performance, security events, and audit trails.
* **Metadata Endpoints (Configuration Discovery):**
    * **Discovery Endpoint (Similar to OIDC Discovery):** Consider providing a metadata endpoint (e.g., `/.well-known/keyring-configuration`) that exposes configuration details about the Keyring, such as:
        * Encryption and decryption endpoint URLs.
        * Supported cryptographic algorithms (AES-256-GCM, AES-256-CTR, HMAC-SHA-256, HKDF).
        * URLs of trusted Authorization Servers (JWKS endpoints).
        * Key rotation policy (e.g., rotation frequency).
        * Service documentation links.
    * **Purpose:** This metadata endpoint allows clients and administrators to programmatically discover and verify the Keyring's configuration, making integration and management easier and more transparent.
* **Role-Based Access Control (RBAC) for Keyring Admin:** Implement strong Role-Based Access Control for the Keyring admin interface.  Restrict access to sensitive administrative functions (like Master Key management, AS configuration) to only authorized administrators with proper credentials.
* **Secure Deployment and Hardening:** Apply security hardening best practices to the Keyring server infrastructure:
    * Secure operating system configuration.
    * Firewall rules and network segmentation.
    * Regular security patching and updates.
    * Intrusion detection and prevention systems.
* **Audit Logging and Security Monitoring:** Comprehensive audit logging of all Keyring operations (especially administrative actions, key management events, and authorization decisions).  Implement security monitoring and alerting to detect and respond to suspicious activities.
* **Rate Limiting and DoS Protection:** Implement rate limiting and other DoS protection mechanisms to prevent abuse of the Keyring's encryption and decryption endpoints.

<div style="break-after:page"></div>

## Real-World Scenario

We illustrate the process of securely sharing data between Alice and Bob, where Alice wants to share a vacation photo with Bob.

### Prerequisites

Alice uses an application (Client) that allows her authenticate via the Authorization Server (AS) and store, retrieve, and share encrypted files on the remote data store (RS1). Additionally, the Client has access to the remote keyring (RS2), which provides identity-based cryptographic functions.  The Client has simultaneous access to both the RS1 and RS2. Alice also knows that Bob can obtain authorized access to RS1 and RS2.

Notes:

* The interaction with RS1 is not detailed in this proposal and is considered out of scope.
* In this context, RS2 represents RS in the provided sequence diagrams.
* The Client application acts as the intermediary, interacting with both RS1 and RS2.

### Use Case

Alice opens her vacation photo in the Client and enters Bob's email address in the "Share with:" field. She then clicks the "Share" button. The Client encrypts the photo on the client side using RS2's identity-based cryptographic functions and stores the encrypted photo along with its metadata in RS1.

Afterward, Alice notifies Bob that he can access the photo by sending him a shared link to the encrypted file stored in RS1.

Bob can open the shared link after authenticating via AS. His Client retrieves the encrypted photo along with its metadata from RS1, and decrypts it on the client side using RS2's identity-based cryptographic functions. Finally Bob saves the decrypted photo to his local storage.

Notes:

* The encrypted files and associated metadata from the encryption process are persistently stored on RS1 by the Client.
* The keyring can input its URL into the Identity AAD (Identity AAD = Identity nonce || Content hash || Keyring URL) before wrapping the Content Encryption Key. As a result, the Client knows which remote keyring must be used to unwrap the Content Encryption Key ciphertext. This allows Alice to use her dedicated remote keyring, RS2, to encrypt her vacation photo shared with Bob, while Bob can use his remote keyring, RS3, to encrypt his vacation photo shared with Alice, both users using the same remote data store, RS1.
* Alice can have a single dedicated remote Keyring and use multiple sharing services, such as (a) a remote photo store and (b) a remote document repository, each with its own AS provider and respective registered Client. With a properly configured Keyring, and both Clients having Alice's Keyring URL set in their account configuration, such a setup will work without any issues. As long as Bob is registered with both services, Alice can share an encrypted photo and document with him using her single remote Keyring.

### Summary

In essence, RS2, RS3 are the crypto engines and key managers, while RS1 is the data and metadata repository. The Client orchestrates the interaction between them.

<div style="break-after:page"></div>

## Conclusion

Overall, the proposal presents a robust framework for secure content sharing using identity-based encryption and modern cryptographic practices.

TBD