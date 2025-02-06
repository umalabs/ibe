# Identity-Based Symmetric Key Encryption Mechanisms

## Acronyms

* RS: Resource Server

**Sequence Diagram for Encryption:**

```plantuml
@startuml
' --- Client ---
participant "Content Hash\nGenerator\n(HMAC-SHA-256)" as HashGen
participant "Content Hash Key\nRND Generator" as HashKeyRND
participant "Content Encryption\n(AES-256-CRT)" as DataEnc
participant "Content Enc. Key\nRND Generator" as DataEncKeyRND
participant "Content IV\nRND Generator" as DataIV_RND
participant "Access\nToken" as AT

' --- Client Inputs ---
participant "Content\nPlaintext" as PlainDataInput
participant Entropy_Client as "Entropy"

' --- Client Outputs ---
participant "Content\nCiphertext" as CipheredDataOutput

' --- Client-Side Generated Metadata ---
participant "Content Hash Key" as HashKeyOutput
participant "Content IV" as DataIVOutput

' --- RS ---
participant "Identity Enc. Key\nGenerator\n(HMAC-SHA-256)" as IKG
participant "Content Enc. Key\nEncryption\n(AES-256-GCM)" as DKE
participant "nonce RND\nGenerator\n(CTR-DRBG-256)" as NRG_DK
participant "nonce RND\nGenerator\n(CTR-DRBG-256)" as NRG_ID
participant "Authorization\nAssessment" as AA

' --- RS Inputs ---
participant Entropy_RS as "Entropy"
participant Masterkey as "Master Key"

' --- RS-Side Generated Metadata ---
participant "Content Enc. Key\nCiphertext" as CipheredDataEncKeyOutput
participant "Identity\nAAD Tag" as IdentityAADTagOutput
participant "Identity\nIV" as IdentityIVOutput
participant "Identity\nAAD" as IdentityAADOutput

box "Client Data" #White
    participant PlainDataInput
    participant CipheredDataOutput
    participant AT
    participant Entropy_Client
end box

box "Client"
    participant HashGen
    participant HashKeyRND
    participant DataEnc
    participant DataEncKeyRND
    participant DataIV_RND
end box

box "Client-Side Generated Metadata" #LightBlue
    participant HashKeyOutput
    participant DataIVOutput
end box

box "Mixed Metadata" #LightBlue
    participant IdentityAADOutput
end box

box "RS-Side Generated Metadata" #LightBlue
    participant CipheredDataEncKeyOutput
    participant IdentityIVOutput
    participant IdentityAADTagOutput
end box

box "RS"
    participant DKE
    participant IKG
    participant NRG_DK
    participant NRG_ID
    participant AA
end box

box "RS Data" #White
    participant Entropy_RS
    participant Masterkey
end box

Entropy_RS -> NRG_ID: Entropy
Entropy_RS -> NRG_DK: Entropy
Masterkey -> IKG: Master Key

Entropy_Client -> HashKeyRND: Entropy
Entropy_Client -> DataIV_RND: Entropy

AT->AA: JWT
activate AA

PlainDataInput -> HashGen: Content Plaintext
' --- Content Hash Generation ---
HashGen -> HashKeyRND: Get Content Hash Key
' --- Hash Key Generation ---
activate HashKeyRND
HashKeyRND -> HashKeyRND: Generate\nRandom\nContent Hash Key
HashKeyRND --> HashGen: Content Hash Key
deactivate HashKeyRND
activate HashGen
HashKeyRND --> HashKeyOutput: Content Hash Key
HashGen -> HashGen: Generate\nContent Hash

' --- Identity AAD Generation ---
HashGen --> IdentityAADOutput: Content Hash

deactivate HashGen

PlainDataInput -> DataEnc: Content Plaintext
' --- Content Encryption ---
DataEnc -> DataEncKeyRND: Get Content Enc. Key
' --- Content Encryption Key Generation ---
activate DataEncKeyRND
DataEncKeyRND -> DataEncKeyRND: Generate\nRandom\nContent Enc. Key
DataEncKeyRND --> DataEnc: Content Enc. Key
deactivate DataEncKeyRND
DataEncKeyRND -> DKE: Content Encryption Key


DataEnc -> DataIV_RND: Get Content IV
' --- Content IV Generation ---
activate DataIV_RND
DataIV_RND -> DataIV_RND: Generate\nRandom\nContent IV
DataIV_RND --> DataEnc: Content IV
deactivate DataIV_RND
activate DataEnc
DataIV_RND --> DataIVOutput: Content IV

DataEnc -> DataEnc: Encrypt Content
DataEnc --> CipheredDataOutput: Content Ciphertext
deactivate DataEnc

' --- Identity Enc. Key Generation ---
DKE -> IKG: Get Identity\nEncryption Key

IKG -> NRG_ID: Get Identity nonce

' --- Identity nonce Generation ---
activate NRG_ID
NRG_ID -> NRG_ID: Generate\nRandom\nIdentity nonce
NRG_ID --> IKG: Identity nonce
deactivate NRG_ID
NRG_ID --> IdentityAADOutput: Identity nonce
note right of IKG: Identity Data = Identity nonce || User ID


AA-> IKG: User ID
deactivate AA
activate IKG


IKG -> IKG: Generate\nIdentity Enc. Key
IKG --> DKE: Identity Enc. Key
deactivate IKG

DKE -> NRG_DK: Get Identity IV

' --- Identity IV Generation ---
activate NRG_DK
NRG_DK --> NRG_DK: Generate\nRandom\nIdentity IV
NRG_DK --> DKE: Identity IV
deactivate NRG_DK
NRG_DK --> IdentityIVOutput: Identity IV

note right of IdentityAADOutput: Identity AAD = Identity nonce || Content Hash 
IdentityAADOutput -> DKE: Identity AAD

' --- Content Encryption ---
' --- Content Key Encryption ---
activate DKE
DKE --> DKE: Encrypt\nContent Enc. Key
DKE --> CipheredDataEncKeyOutput: Content Encryption Key Ciphertext
DKE --> DKE: Generate\nAAD Tag
DKE --> IdentityAADTagOutput: Identity\nAAD Tag

deactivate DKE



@enduml
```

