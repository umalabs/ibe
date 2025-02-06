# Identity-Based Symmetric Key Encryption Mechanisms

## Acronyms

* RS: Resource Server

**Sequence Diagram for Encryption:**

```plantuml
@startuml
' --- Client ---
participant "Content Hash\nGenerator\n(HMAC-SHA-256)" as ContentHashGen
participant "Content Hash Key\nRND Generator" as ContentHashKeyRND
participant "Content Encryption\n(AES-256-CRT)" as ContentEncryption
participant "Content Enc. Key\nRND Generator" as ContentEncKeyRND
participant "Content IV\nRND Generator" as ContentIV_RND

' --- Client Inputs ---
participant "Content\nPlaintext" as ContentPlaintext
participant "Entropy" as ClientEntropy
participant "Access\nToken" as AccessToken

' --- Client Outputs ---
participant "Content\nCiphertext" as ContentCiphertext

' --- Client-Side Generated Metadata ---
participant "Content Hash Key" as ContentHashKeyMetadata
participant "Content IV" as ContentIVMetadata

' --- RS ---
participant "Identity Enc. Key\nGenerator\n(HMAC-SHA-256)" as IdentityEncKeyGen
participant "Content Enc. Key\nEncryption\n(AES-256-GCM)" as ContentEncKeyEncryption
participant "Content nonce\nRND Generator\n(CTR-DRBG-256)" as ContentNonceRNDGen
participant "Identity nonce\nRND Generator\n(CTR-DRBG-256)" as IdentityNonceRNDGen
participant "Authorization\nAssessment" as AuthorizationAssessment

' --- RS Inputs ---
participant "Entropy" as RSEntropy
participant "Master Key" as Masterkey

' --- RS-Side Generated Metadata ---
participant "Content Enc. Key\nCiphertext" as ContentEncKeyCiphertextMetadata
participant "Identity\nAAD Tag" as IdentityAADTagMetadata
participant "Identity\nIV" as IdentityIVMetadata

' --- Mixed Metadata ---
participant "Identity\nAAD" as IdentityAAD

box "Client Data" #White
    participant ContentPlaintext
    participant ContentCiphertext
    participant AccessToken
    participant ClientEntropy
end box

box "Client"
    participant ContentHashGen
    participant ContentHashKeyRND
    participant ContentEncryption
    participant ContentEncKeyRND
    participant ContentIV_RND
end box

box "Client-Side Generated Metadata" #LightBlue
    participant ContentHashKeyMetadata
    participant ContentIVMetadata
end box

box "Mixed Metadata" #LightBlue
    participant IdentityAAD
end box

box "RS-Side Generated Metadata" #LightBlue
    participant ContentEncKeyCiphertextMetadata
    participant IdentityIVMetadata
    participant IdentityAADTagMetadata
end box

box "RS"
    participant ContentEncKeyEncryption
    participant IdentityEncKeyGen
    participant ContentNonceRNDGen
    participant IdentityNonceRNDGen
    participant AuthorizationAssessment
end box

box "RS Data" #White
    participant RSEntropy as "Entropy"
    participant Masterkey as "Master Key"
end box

RSEntropy -> IdentityNonceRNDGen: Entropy
RSEntropy -> ContentNonceRNDGen: Entropy
Masterkey -> IdentityEncKeyGen: Master Key

ClientEntropy -> ContentHashKeyRND: Entropy
ClientEntropy -> ContentIV_RND: Entropy

AccessToken->AuthorizationAssessment: JWT
activate AuthorizationAssessment

ContentPlaintext -> ContentHashGen: Content Plaintext
' --- Content Hash Generation ---
ContentHashGen -> ContentHashKeyRND: Get Content Hash Key
' --- Hash Key Generation ---
activate ContentHashKeyRND
ContentHashKeyRND -> ContentHashKeyRND: Generate\nRandom\nContent Hash Key
ContentHashKeyRND --> ContentHashGen: Content Hash Key
deactivate ContentHashKeyRND
activate ContentHashGen
ContentHashKeyRND --> ContentHashKeyMetadata: Content Hash Key
ContentHashGen -> ContentHashGen: Generate\nContent Hash

' --- Identity AAD Generation ---
ContentHashGen --> IdentityAAD: Content Hash

deactivate ContentHashGen

ContentPlaintext -> ContentEncryption: Content Plaintext
' --- Content Encryption ---
ContentEncryption -> ContentEncKeyRND: Get Content Enc. Key
' --- Content Encryption Key Generation ---
activate ContentEncKeyRND
ContentEncKeyRND -> ContentEncKeyRND: Generate\nRandom\nContent Enc. Key
ContentEncKeyRND --> ContentEncryption: Content Enc. Key
deactivate ContentEncKeyRND
ContentEncKeyRND -> ContentEncKeyEncryption: Content Encryption Key


ContentEncryption -> ContentIV_RND: Get Content IV
' --- Content IV Generation ---
activate ContentIV_RND
ContentIV_RND -> ContentIV_RND: Generate\nRandom\nContent IV
ContentIV_RND --> ContentEncryption: Content IV
deactivate ContentIV_RND
activate ContentEncryption
ContentIV_RND --> ContentIVMetadata: Content IV

ContentEncryption -> ContentEncryption: Encrypt Content
ContentEncryption --> ContentCiphertext: Content Ciphertext
deactivate ContentEncryption

' --- Identity Enc. Key Generation ---
ContentEncKeyEncryption -> IdentityEncKeyGen: Get Identity\nEncryption Key

IdentityEncKeyGen -> IdentityNonceRNDGen: Get Identity nonce

' --- Identity nonce Generation ---
activate IdentityNonceRNDGen
IdentityNonceRNDGen -> IdentityNonceRNDGen: Generate\nRandom\nIdentity nonce
IdentityNonceRNDGen --> IdentityEncKeyGen: Identity nonce
deactivate IdentityNonceRNDGen
IdentityNonceRNDGen --> IdentityAAD: Identity nonce
note right of IdentityEncKeyGen: Identity Data = Identity nonce || User ID


AuthorizationAssessment-> IdentityEncKeyGen: User ID
deactivate AuthorizationAssessment
activate IdentityEncKeyGen


IdentityEncKeyGen -> IdentityEncKeyGen: Generate\nIdentity Enc. Key
IdentityEncKeyGen --> ContentEncKeyEncryption: Identity Enc. Key
deactivate IdentityEncKeyGen

ContentEncKeyEncryption -> ContentNonceRNDGen: Get Identity IV

' --- Identity IV Generation ---
activate ContentNonceRNDGen
ContentNonceRNDGen --> ContentNonceRNDGen: Generate\nRandom\nIdentity IV
ContentNonceRNDGen --> ContentEncKeyEncryption: Identity IV
deactivate ContentNonceRNDGen
ContentNonceRNDGen --> IdentityIVMetadata: Identity IV

note right of IdentityAAD: Identity AAD = Identity nonce || Content Hash 
IdentityAAD -> ContentEncKeyEncryption: Identity AAD

' --- Content Key Encryption ---
activate ContentEncKeyEncryption
ContentEncKeyEncryption --> ContentEncKeyEncryption: Encrypt\nContent Enc. Key
ContentEncKeyEncryption --> ContentEncKeyCiphertextMetadata: Content Encryption Key Ciphertext
ContentEncKeyEncryption --> ContentEncKeyEncryption: Generate\nAAD Tag
ContentEncKeyEncryption --> IdentityAADTagMetadata: Identity\nAAD Tag

deactivate ContentEncKeyEncryption

@enduml
```

