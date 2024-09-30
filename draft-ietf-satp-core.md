---

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  tocdepth: 4
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: o-*+
  compact: yes
  subcompact: no

title: Secure Asset Transfer Protocol (SATP) Core
abbrev: SATP Core
docname: draft-ietf-satp-core-latest
category: info

ipr: trust200902
area: "Applications and Real-Time"
workgroup: "Secure Asset Transfer Protocol"

stream: IETF
keyword: Internet-Draft
consensus: true

venue:
  group: "Secure Asset Transfer Protocol"
  type: "Working Group"
  mail: "sat@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/sat/"
  github: "ietf-satp/draft-ietf-satp-core"
  latest: "https://ietf-satp.github.io/draft-ietf-satp-core/draft-ietf-satp-core.html"

author:
  -
    ins: M. Hargreaves
    name: Martin Hargreaves
    organization: Quant Network
    email: martin.hargreaves@quant.network
  -
    ins: T. Hardjono
    name: Thomas Hardjono
    organization: MIT
    email: hardjono@mit.edu
  -
    ins: R. Belchior
    name: Rafael Belchior
    organization: INESC-ID, Técnico Lisboa, Blockdaemon
    email: rafael.belchior@tecnico.ulisboa.pt
  -
    ins: V. Ramakrishna
    name: Venkatraman Ramakrishna
    organization: IBM
    email: vramakr2@in.ibm.com

informative:
  NIST:
    author:
    - ins: D. Yaga
    - ins: P. Mell
    - ins: N. Roby
    - ins: K. Scarfone
    date: October 2018
    target: https://doi.org/10.6028/NIST.IR.8202
    title: NIST Blockchain Technology Overview (NISTR-8202)

  MICA:
    author:
    - ins: European Commission
    date: June 2023
    target: https://www.esma.europa.eu/esmas-activities/digital-finance-and-innovation/markets-crypto-assets-regulation-mica
    title: EU Directive on Markets in Crypto-Assets Regulation (MiCA)

  ARCH:
    author:
    - ins: T. Hardjono
    - ins: M. Hargreaves
    - ins: N. Smith
    - ins: V. Ramakrishna
    date: June 2024
    target: https://datatracker.ietf.org/doc/draft-ietf-satp-architecture/
    title: Secure Asset Transfer (SAT) Interoperability Architecture
    
  RFC5939:
    author:
    - ins: F. Andreasen
    date: September 2010
    target: https://www.rfc-editor.org/info/rfc5939
    title: Session Description Protocol (SDP) Capability Negotiation

normative:
  JWT: RFC7519
  REQ-LEVEL: RFC2119
  
--- abstract

This memo describes the Secure Asset Transfer (SAT) Protocol for digital assets. SAT is a protocol operating between two gateways that conducts the transfer of a digital asset from one gateway to another, each representing their corresponding digital asset networks. The protocol establishes a secure channel between the endpoints and implements a 2-phase commit (2PC) to ensure the properties of transfer atomicity, consistency, isolation and durability.

--- middle

# Introduction

{: #introduction-doc}

This memo proposes a secure asset transfer protocol (SATP) that is intended to be deployed between two gateway endpoints to transfer a digital asset from an origin asset network to a destination asset network.
Readers are directed first to {{ARCH}} for a description of the architecture underlying the current protocol.

Both the origin and destination asset networks are assumed to be opaque
in the sense that the interior construct of a given network
is not read/write accessible to unauthorized entities.

The protocol utilizes the asset burn-and-mint paradigm whereby the asset
to be transferred is permanently disabled or destroyed (burned)
at the origin asset network and is re-generated (minted) at the destination asset network.
This is achieved through the coordinated actions of the peer gateways
handling the unidirectional transfer at the respective networks.

A gateway is assumed to be trusted to perform the tasks involved in the asset transfer.

The overall aim of the protocol is to ensure that the state of assets
in the origin and destination networks remain consistent,
and that asset movements into (out of) networks via gateways can be accounted for.

There are several desirable technical properties of the protocol.
The protocol must ensure that the properties of atomicity, consistency,
isolation, and durability (ACID) are satisfied.

The requirement of consistency implies that the
asset transfer protocol always leaves both asset networks
in a consistent state (that the asset is located in
one system/network only at any time).

Atomicity means that the protocol must guarantee
that either the transfer commits (completes) or entirely fails,
where failure is taken to mean there is no change to the
state of the asset in the origin (sender) asset network.

The property of isolation means that while a transfer
is occurring to a digital asset from an origin network,
no other state changes can occur to the asset.

The property of durability means that once
the transfer has been committed by both gateways,
that this commitment must hold regardless of subsequent
unavailability (e.g. crash) of the gateways implementing the SAT protocol.

All messages exchanged between gateways are assumed to run over TLS1.2,
and the endpoints at the respective gateways are associated with
a certificate indicating the legal owner (or operator) of the gateway.

# Conventions used in this document

{: #conventions}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL"
in this document are to be interpreted as described in RFC 2119 {{REQ-LEVEL}}.

In this document, these words will appear with that interpretation
only when in ALL CAPS. Lower case uses of these words are not to be
interpreted as carrying significance described in RFC 2119.

# Terminology

{: #terminology-doc}

The following are some terminology used in the current document, some borrowed from {{NIST}}:

- Digital asset: digital representation of a value or of a right that is able to be
  transferred and stored electronically using distributed ledger technology or similar technology {{MICA}}.

- Asset network: A monolithic system or a set of distributed systems that manage digital assets.

- Client application: This is the application employed by a user
  to interact with a gateway.

- Gateway: The computer system functionally capable of acting
  as a gateway in an asset transfer.

- Sender gateway: The gateway that initiates a unidirectional asset transfer.

- Recipient gateway: The gateway that is the recipient side of
  a unidirectional asset transfer.

- Claim: An assertion made by an Entity {{JWT}}.

- Claim Type: Syntax used for representing a Claim Value {{JWT}}.

- Gateway Claim: An assertion made by a Gateway regarding the status or
  condition of resources (e.g. assets, public keys, etc.)
  accessible to that gateway (e.g. within its asset network or system).

In the remainder of this document, for brevity of description the term “asset network” will often be shorted to "network".

# The Secure Asset Transfer Protocol

{: #satp-protocol}

## Overview

{: #satp-overview}

The Secure Asset Transfer Protocol (SATP) is a gateway-to-gateway protocol used by a sender gateway with a recipient gateway to perform a unidirectional transfer of a digital asset.

The protocol defines a number of API endpoints, resources and identifier definitions, and message flows corresponding to the asset transfer between the two gateways.

The current document pertains to the interaction between gateways through API2 [SATP-ARCH].

```
                 +----------+                +----------+
                 |  Client  |                | Off-net  |
          ------ |   (App)  |                | Resource |
          |      +----------+                +----------+
          |           |                      |   API3   |
          |           |                      +----------+
          |           |                           ^
          |           V                           |
          |      +---------+                      |
          V      |   API1  |                      |
       +-----+   +---------+----+        +----+---------+   +-----+
       |     |   |         |    |        |    |         |   |     |
       | Net.|   | Gateway |API2|        |API2| Gateway |   | Net.|
       | NW1 |---|    G1   |    |<------>|    |    G2   |---| NW2 |
       |     |   |         |    |        |    |         |   |     |
       +-----+   +---------+----+        +----+---------+   +-----+
```

{: #satp-fig-overview}

## SAT Model

{: #satp-model}

The model for SATP is shown in Figure 1 [SATP-ARCH].
The Client (application) interacts with its local gateway (G1) over an interface (API1) in order to provide instructions to the gateway with regards to actions to assets and related resources located in the local system or network (NW1).

Gateways interact with each other over a gateway interface (API2). A given gateway may be required to access resources that are not located in network NW1 or network NW2. Access to these types of resources are performed over an off-network interface (API3).

## Stages of the Protocol

{: #satp-flowtypes}

The SAT protocol defines three (3) stages for a unidirectional asset transfer. These stages occur following the transfer set-up.

- Transfer Initiation stage (Stage-1):
  These flows deal with commencing a transfer from one gateway to another. Several tasks are involved, including (but not limited to):
  (i) gateway identification and mutual authentication;
  (ii) exchange of asset type (definition) information;
  (iii) verification of the asset definition, and others.

- Lock-Assertion stage (Stage-2):
  These flows deal with the conveyance of signed assertions from the sender gateway to the receiver gateway
  regarding the locked status of an asset at the origin asset network.

- Commitment Preparation and Finalization stage (Stage-3):
  These flows deal with the asset transfer and commitment establishment between two gateways.

In order to clarify discussion, the interactions between the peer gateways prior to transfer initiation stage is referred to as the setup stage (Stage-0), which is outside the scope of the current specification.

The Stage-1, Stage-2 and Stage-3 flows will be discussed below.

## Gateway Cryptographic Keys

SATP recognizes the following cryptographic keys which are intended for distinct purposes within the different stages of the protocol.

- Gateway signature public key-pair: This is the key-pair utilized by a gateway to digitally sign assertions and receipts.

- Gateway secure channel establishment public key-pair: This is the key-pair utilized by peer gateways to establish a secure channel (e.g. TLS) for a transfer session.

- Gateway device-identity public key pair: This is the key-pair that identifies the unique hardware device underlying a gateway.
  
- Gateway owner-identity public key pair: This is the key-pair that identifies the owner (e.g. legal entity) who is the legal owner of a gateway.

# SATP Message Format, identifiers and Descriptors

{: #satp-messages-identifiers}

## Overview

{: #satp-message-identifier-overview}

This section describes the SATP message-types, the format of the messages exchanged between two gateways, the format for resource descriptors and other related parameters.

The mandatory fields are determined by the message type exchanged between the two gateways (see Section 7).

## SATP Message Format and Payloads

{: #satp-message-format}

SATP messages are exchanged between peer gateways, where depending on the message type one gateway may act as a client of the other (and vice versa).

### Protocol version

This refers to SATP protocol Version, encoded as "major.minor" (separated by a period symbol).

### Message Type

This refers to the type of request or response to be conveyed in the message.

The possible values are:

- transfer-proposal-msg: This is the transfer proposal message from the sender gateway carrying the set of proposed parameters for the transfer.

- proposal-receipt-msg: This is the signed receipt message indicating acceptance of the proposal by the receiver gateway.

- proposal-reject-msg: This is an explicit reject message from the receiver gateway, indicating a rejection of the proposal and an immediate session termination.

- transfer-commence-msg: Request to begin the commencement of the asset transfer.

- ack-commence-msg: Response to accept to the commencement of the asset transfer.

- lock-assert-msg: Sender gateway has performed the lock of the asset in the origin network.

- assertion-receipt-msg: Receiver gateway acknowledges receiving of the signed lock-assert-msg.

- commit-prepare-msg: Sender gateway requests the start of the commitment stage.

- ack-prepare-msg: Receiver gateway acknowledges receiving the previous commit-prepare-msg and agrees to start the commitment stage.

- commit-final-msg: Sender gateway has performed the extinguishment (burn) of the asset in the origin network.

- ack-commit-final-msg: Receiver gateway acknowledges receiving of the signed commit-final-msg and has performed the asset creation and assignment in the destination network.

- commit-transfer-complete-msg: Sender gateway indicates closure of the current transfer session.

### Digital Asset Identifier

This is the unique identifier (e.g. UUIDv2) that uniquely identifies the digital asset in the origin network which is to be transferred to the destination network.

The digital asset identifier is a value that is derived by the applications utilized by the originator and the beneficiary prior to starting the asset transfer.

The mechanism used to derive the digital asset identifier is outside the scope of the current document.

### Transfer-Context ID:

This is the unique immutable identifier (e.g. UUIDv2) representing the application layer context of a single unidirectional transfer. The transfer-context is a complex data structure (e.g. in JSON format) that contains all information related to a SATP execution instance. Examples of information contained in a transfer-context may include identifiers of sessions, gateways, networks or assets related to the specific SATP execution instance. Typically, a transfer-context may be retrieved from a Registry via an API3 call

### Session ID:

This is the unique identifier (e.g. UUIDv2) representing a session between two gateways handling a single unidirectional transfer. This may be derived from the Transfer-Context ID at the application level. There may be several session IDs related to a SATP execution instance. Only one Session ID may be active for a given SATP execution instance. Session IDs may be stored in the transfer-context for audit trail purposes.

### Sequence Number:

This is a monotonically increasing counter value uniquely representing a message from a session. This can be utilized to assist the peer gateways when they are processing multiple simultaneous unrelated transfers.

### Gateway Credential Type

This is the type of authentication mechanism supported by the gateway (e.g. SAML, OAuth, X.509)

### Gateway Credential

This payload is the actual credential of the gateway (token, certificate, string, etc.).

### Payload Hash

This is the hash of the current message payload.

### Signature Algorithms Supported

This is the list of digital signature algorithm supported by a gateway, with the base default being the NIST ECDSA standard.

### Message Signature

This payload is the actual the ECDSA signature portion over a message.

### Lock assertion Claims and Format
This is the format of the set of claims regarding the state of the asset in the origin network. 
The claims are network-dependent in the sense that different asset networks or systems may utilize a different asset locking (disablement) mechanism.

## Negotiation of Security Protocols and Parameters

{: #satp-negotiation-params-sec}

The peer gateways in SATP must establish a TLS session between them prior to starting the transfer initiation stage (Stage-0). The TLS session continues until the transfer is completed at the end of the commitment establishment stage (Stage-3).

In the following, the sender gateway is referred to as the client while the received gateway as the server.

### TLS Secure Channel Establishment

{: #satp-tls-Established-sec}

TLS 1.2 or higher MUST be implemented to protect gateway communications. TLS 1.3 or higher SHOULD be implemented where both gateways support TLS 1.3 or higher.

### Client offers supported credential schemes

{: #satp-client-offers-sec}

The client sends a JSON block containing the supported credential schemes, such as OAuth2.0 or SAML, in the "Credential Scheme" field of the SATP message.

### Server selects supported credential scheme

{: #satp-server-selects-sec}

The server (recipient Gateway) selects one acceptable credential scheme from the offered schemes, returning the selection in the "Credential Scheme" field of the SATP message. If no acceptable credential scheme was offered, an HTTP 511 "Network Authentication Required" error is returned.

### Client asserts or proves identity

{: #client-procedure-sec}

The details of the assertion/verification step are specific to the chosen credential scheme and are outside the scope of this document.

### Sequence numbers initialized

{: #sequence-numbers-sec}

Sequence numbers are used to allow the server to correctly order operations from the client. Some operations may be asynchronous, synchronous, or idempotent with duplicate requests handled differently according to the use case. The initial sequence number is proposed by the client (sender gateway) after credential verification is finalized. The server (receiver gateway) MUST respond with the same sequence number to indicate acceptance. The client increments the sequence number with each new request. Sequence numbers can be reused for retries in the event of a gateway timeout.

### Messages can now be exchanged

{: #satp-msg-exchnge-sec}

Handshaking is complete at this point, and the client can send SAT messages to perform actions on resources, which MAY reference the SAT Payload field.

## Asset Profile Identification

{: #satp-asset-profile-negotiation}

The client and server must mutually agree on the asset type or profile that is the subject of the current transfer. The client provides the server with the asset identification number, or the server may provide the client with the asset identification numbers for the digital asset it supports. Formal specification of asset identification is outside the scope of this document. Globally numbering digital asset types or profiles is expected to be performed by a legally recognized entity.

# Overview of Message Flows

{: #satp-flows-overview-section}

The SATP message flows are logically divided into three (3) stages [SATP-ARCH], with the preparatory stage denoted as Stage-0. How the tasks are achieved in Stage-0 is out of scope for the current specification.

The Stage-1 flows pertains to the initialization of the transfer between the two gateways.

After both gateways agree to commence the transfer at the start of Stage-2, the sender gateway G1 must deliver a signed assertion that it has performed the correct lock (burn) on the asset in origin network (NW1).

If that assertion is accepted by gateway G2, it must in return transmit a signed receipt to gateway G1 that it has created (minted) a temporary asset in destination network (NW2).

The Stage-3 flows commits gateways G1 and G2 to the burn and mint in Stage-2. The sender gateway G1 must make the lock on the asset in origin network NW1 to be permanent (burn). The receiver gateway G2 must assign (mint) the asset in the destination network NW2 to the correct beneficiary.

The reader is directed to [SATP-ARCH] for further discussion of this model.

```
       App1  NW1          G1                     G2          NW2    App2
      ..|.....|............|......................|............|.....|..
        |     |            |       Stage 1        |            |     |
        |     |            |                      |            |     |
        |     |       (1.1)|--Transf. Proposal -->|            |     |
        |     |            |                      |            |     |
        |     |            |<--Proposal Receipt---|(1.2)       |     |
        |     |            |                      |            |     |
        |     |       (1.3)|<--Transf. Commence-->|            |     |
        |     |            |                      |            |     |
        |     |            |<--- ACK Commence --->|(1.4)       |     |
        |     |            |                      |            |     |
      ..|.....|............|......................|............|.....|..
        |     |            |       Stage 2        |            |     |
        |     |            |                      |            |     |
        |     |<---Lock----|(2.1)                 |            |     |
        |     |            |                      |            |     |
        |     |       (2.2)|--- Lock-Assertion--->|            |     |
        |     |            |                      |            |     |
        |     |            |                 (2.3)|----Bcast-->|     |
        |     |            |                      |            |     |
        |     |            |<--Assertion Receipt--|(2.4)       |     |
        |     |            |                      |            |     |
      ..|.....|............|......................|............|.....|..
        |     |            |       Stage 3        |            |     |
        |     |            |                      |            |     |
        |     |       (3.1)|----Commit Prepare--->|            |     |
        |     |            |                      |            |     |
        |     |            |                 (3.2)|----Mint--->|     |
        |     |            |                      |            |     |
        |     |            |<--- Commit Ready ----|(3.3)       |     |
        |     |            |                      |            |     |
        |     |<---Burn----|(3.4)                 |            |     |
        |     |            |                      |            |     |
        |     |       (3.5)|---- Commit Final --->|            |     |
        |     |            |                      |            |     |
        |     |            |                 (3.6)|---Assign-->|     |
        |     |            |                      |            |     |
        |     |            |<-----ACK Final-------|(3.7)       |     |
        |     |            |                      |            |     |
        |     |            |                      |            |     |
        |     |<---Bcast---|(3.8)                 |            |     |
        |     |            |                      |            |     |
        |     |       (3.9)|--Transfer Complete-->|            |     |
      ..|.....|............|......................|............|.....|..
```

# Identity and Asset Verification Stage (Stage 0)

{: #satp-Stage0-section}

Prior to commencing the asset transfer from the sender gateway (client) to the recipient gateway (server), 
both gateways must perform a number of verifications steps pSATP-ARCH]. 
The types of information required by both the sender and recipient are use-case dependent and asset-type dependent.

The verifications include, but not limited to, the following:

- Verification of the gateway signature public key: The sender gateway and receiver gateway must validate their respective signature public keys that will later be used to sign assertions and claims. This may include validating the X509 certificates of these keys.

- Gateway owner verification:
  This is the verification of the identity (e.g. LEI) of the owners of the gateways.

- Gateway device and state validation:
  This is the device attestation evidence [RATS]
  that a gateway must collect and convey to each other,
  where a verifier is assumed to be available to decode,
  parse and appraise the evidence.

- Originator and beneficiary identity verification:
  This is the identity and public-key of the entity (originator)
  in the origin network seeking to transfer the asset to
  another entity (beneficiary) in the destination network.

These are considered out of scope in the current specifications,
and are assumed to have been successfully completed prior to
the commencement of the transfer initiation flow.
The reader is directed to [SATP-ARCH] for further discussion regarding Stage-0.

# Transfer Initiation Stage (Stage 1)

{: #satp-stage1-section}

This section describes the transfer initiation stage, where the sender gateway and the receiver gateway prepare for the start of the asset transfer.

The sender gateway proposes the set of transfer parameters and asset-related artifacts for the transfer to the receiver gateway. These are contained in the Transfer Initiation Claims.

If the receiver gateway accepts the proposal, it returns a signed receipt message for the proposal indicating it agrees to proceed to the next stage. If the receiver gateway rejects any parameters or artifacts in the proposal, it can provide a counteroffer to the sender gateway by responding with a proposal reject message carrying alternative parameters.

Gateways MUST support the use of the HTTP GET and POST methods
defined in RFC 2616 [RFC2616] for the endpoint.

Clients (sender gateway) MAY use the HTTP GET or POST methods to send messages
in this stage to the server (recipient gateway).
If using the HTTP GET method, the request parameters may be
serialized using URI Query String Serialization.

(NOTE: Flows occur over TLS. Nonces are not shown).

## Transfer Initialization Claims

{: #satp-stage1-init-claims}
This is set of artifacts pertaining to the asset that
must be agreed upon between the client (sender
gateway) and the server (recipient gateway).

The Transfer Initialization Claims consists of the following:

- digital_asset_id REQUIRED: This is the globally unique identifier for the digital asset
  located in the origin network.

- asset_profile_id REQUIRED: This is the globally unique identifier for the asset-profile
  definition (document) on which the digital asset was issued.

- verified_originator_entity_id REQUIRED: This is the identity data of the originator entity
  (person or organization) in the origin network.
  This information must be verified by the sender gateway.

- verified_beneficiary_entity_id REQUIRED: This is the identity data of the beneficiary entity
  (person or organization) in the destination network.
  This information must be verified by the receiver gateway.

- originator_pubkey REQUIRED. This is the public key of the asset owner (originator)
  in the origin network or system.

- beneficiary_pubkey REQUIRED. This is the public key of the beneficiary
  in the destination network.

- sender_gateway_signature_public_key REQUIRED. This is the public key of the key-pair used by the sender gateway to sign assertions and receipts.

- receiver_gateway_signature_public_key REQUIRED. This is the public key of the key-pair used by the recevier gateway to sign assertions and receipts.

- sender_gateway_id OPTIONAL. This is the identifier of the sender gateway.

- recipient_gateway_id OPTIONAL. This is the identifier of the receiver gateway.

- sender_gateway_network_id REQUIRED. This is the identifier of the
  origin network or system behind the client.

- recipient_gateway_network_id REQUIRED. This is the identifier of the destination
  network or system behind the server.

- sender_gateway_device_identity_pubkey OPTIONAL. The device public key of the sender gateway (client).

- receiver_gateway_device_identity_pubkey OPTIONAL. The device public key of the receiver gateway

- sender_gateway_owner_id OPTIONAL: This is the identity information of the owner or operator
  of the sender gateway.

- receiver_gateway_owner_id OPTIONAL: This is the identity information of the owner or operator
  of the recipient gateway.

## Conveyance of Gateway and Network Capabilities

{: #satp-stage1-conveyance}

This is set of parameters pertaining to the origin network and the destination network, and the technical capabilities supported by the peer gateways.

Some of network-specific parameters regarding the origin network may be relevant for a receiver gateways to evaluate its ability to process the proposed transfer.

For example, the average duration of time of a lock to be held by a sender gateway may inform the receiver gateway about delay expectations.

The network capabilities list is as follows:

- gateway_default_signature_algorithm REQUIRED: The default digital signature algorithm (algorithm-id) used by a gateway to sign claims.

- gateway_supported_signature_algorithms OPTIONAL: The list of other digital signature algorithm (algorithm-id) supported by a gateway to sign claims

- network_lock_type REQUIRED: The default locking mechanism used by a network. These can be (i) timelock, (ii) hashlock, (iii) hashtimelock, and so on (TBD).

- network_lock_expiration_time REQUIRED: The duration of time (in seconds) for a lock to expire in the network.

- gateway_credential_profile REQUIRED: Specify type of auth (e.g., SAML, OAuth, X.509).

- gateway_logging_profile REQUIRED: contains the profile regarding the logging procedure. Default is local store

- gateway_access_control_profile REQUIRED: the profile regarding the confidentiality of the log entries being stored. Default is only the gateway that created the logs can access them.

## Transfer Proposal Message

{: #satp-stage1-init-transfer-proposal}

The purpose of this message is for the sender gateway as the client to initiate an asset transfer session with the receiver gateway as the server.

The client transmits a proposal message that carries the claims related to the asset to be transferred. This message must be signed by the client.

This message is sent from the client to the Transfer Initialization Endpoint at the server.

The parameters of this message consists of the following:

- version REQUIRED: SAT protocol Version (major, minor).

- message_type REQUIRED: urn:ietf:satp:msgtype:transfer-proposal-msg .

- session_id REQUIRED: A unique identifier (e.g. UUIDv2) chosen by the
  client to identify the current session.

- transferContext_id REQUIRED: A unique identifier (e.g. UUIDv2) used to identify
  the current transfer session at the application layer.

- transfer_init_claims: The set of artifacts and parameters as the basis
  for the current transfer.

- transfer_init_claims_format REQUIRED: The format of the transfer initialization claims.

- network_capabilities_list REQUIRED: The set of origin network parameters reported by the client to the server.

- multiple_claims_allowed OPTIONAL: true/false.

- multiple_cancels_allowed OPTIONAL: true/false.

- client signature REQUIRED: The client's signature over the message.

## Transfer Proposal Receipt Message

{: #satp-stage1-init-receipt}

The purpose of this message is for the server to indicate explicit
acceptance of the parameters in the claims  part of the transfer proposal message.

The message must be signed by the server.

The message is sent from the server to the Transfer Proposal Endpoint at the client.

The parameters of this message consists of the following:

- version REQUIRED: SAT protocol Version (major, minor).

- message_type REQUIRED: urn:ietf:satp:msgtype:proposal-receipt-msg.

- session_id REQUIRED: A unique identifier (e.g. UUIDv2) chosen by the
  client to identify the current session.

- transferContext_id REQUIRED: A unique identifier (e.g. UUIDv2) used to identify
  the current transfer session at the application layer.

- hash_transfer_init_claims REQUIRED: Hash of the Transfer Initialization Claims
  received in the Transfer Proposal Message.

- Timestamp REQUIRED: timestamp referring to when
  the Initialization Request Message was received.

Example: TBD.

## Transfer Proposal Reject Message

{: #satp-stage1-init-reject}

The purpose of this message is for the server to indicate explicit
rejection of the Transfer Initialization Claims
in the transfer proposal message.
A reject message is taken to mean an immediate termination of the session.

The message must be signed by the server.

The message is sent from the server to the Transfer Proposal Endpoint at the client.

The parameters of this message consists of the following:

- version REQUIRED: SAT protocol Version (major, minor).

- message_type REQUIRED: urn:ietf:satp:msgtype:proposal-reject-msg.

- session_id REQUIRED: A unique identifier (e.g. UUIDv2) chosen by the
  client to identify the current session.

- transferContext_id REQUIRED: A unique identifier (e.g. UUIDv2) used to identify
  the current transfer session at the application layer.

- hash_transfer_init_claims REQUIRED: Hash of the Transfer Initialization Claims
  received in the Transfer Proposal Message.

- Timestamp REQUIRED: timestamp referring to when
  the Initialization Request Message was received.

Example: TBD.

## Transfer Commence Message

{: #satp-transfer-commence-sec}
The purpose of this message is for the client to signal to
the server that the client is ready to start the transfer of the
digital asset. This message must be signed by the client.

This message is sent by the client as a response to the Transfer Proposal Receipt Message previously
received from the server.

This message is sent by the client to the Transfer Commence Endpoint at the server.

The parameters of this message consists of the following:

- message_type REQUIRED. MUST be the value urn:ietf:satp:msgtype:transfer-commence-msg.

- session_id REQUIRED: A unique identifier (e.g. UUIDv2) chosen earlier
  by client in the Initialization Request Message.

- transferContext_id REQUIRED: A unique identifier (e.g. UUIDv2)
  used to identify the current transfer session at the application layer.

- hash_transfer_init_claims REQUIRED: Hash of the Transfer Initialization Claims
  in the Transfer Proposal message.

- hash_prev_message REQUIRED. The hash of the last message, in this case the
  Transfer Proposal Receipt message.

- client_signature REQUIRED. The digital signature of the client.

For example, the client makes the following HTTP request using TLS
(with extra line breaks for display purposes only):

```

 POST /token HTTP/1.1
 Host: server.example.com
 Authorization: Basic awHCaGRSa3F0MzpnWDFmQmF0M2ZG
 Content-Type: application/x-www-form-urlencoded

{
"message_type": "urn:ietf:satp:msgtype:transfer-commence-msg",
"session_id":"9097hkstgkjvVbNH",
"originator_pubkey":"zGy89097hkbfgkjvVbNH",
"beneficiary_pubkey": "mBGHJjjuijh67yghb",
"sender_net_system": "originNETsystem",
"recipient_net_system":"recipientNETsystem",
"client_identity_pubkey":"fgH654tgeryuryuy",
"server_identity_pubkey":"dFgdfgdfgt43tetr535teyrfge4t54334",
"transfer_init_claims":"nbvcwertyhgfdsertyhgf2h3v4bd3v21",
"hash_prev_message":"DRvfrb654vgreDerverv654nhRbvder4",
"client_signature":"fdw34567uyhgfer45"
}


```

{: #transfer-commence-sec-example}

## Commence Response Message (ACK-Commence)

{: #satp-transfer-commence-resp-sec}
The purpose of this message is for the server to indicate agreement
to proceed with the asset transfer, based on the artifacts
found in the previous Transfer Proposal Message.

This message is sent by the server to the Transfer Commence Endpoint at the client.

The message must be signed by the server.

The parameters of this message consist of the following:

- message_type REQUIRED urn:ietf:satp:msgtype:ack-commence-msg

- session_id REQUIRED: A unique identifier (e.g. UUIDv2) chosen earlier
  by client in the Initialization Request Message.

- transferContext_id REQUIRED: A unique identifier (e.g. UUIDv2)
  used to identify the current transfer session at the application layer.

- hash_prev_message REQUIRED.The hash of the last message, in this case the
  the Transfer Commence Message.

- server_signature REQUIRED. The digital signature of the server.

An example of a success response could be as follows: (TBD).

# Lock Assertion Stage (Stage 2)

{: #satp-stage2-section}

The messages in this stage pertain to the sender gateway providing
the recipient gateway with a signed assertion that the asset in the origin asset network
has been locked or disabled and under the control of the sender gateway.

In the following, the sender gateway takes the role of the client
while the recipient gateway takes the role of the server.

The flow follows a request-response model.
The client makes a request (POST) to the Lock-Assertion Endpoint at the server.

Gateways MUST support the use of the HTTP GET and POST methods
defined in RFC 2616 [RFC2616] for the endpoint.

Clients MAY use the HTTP GET or POST methods to send messages in this stage to the server.
If using the HTTP GET method, the request parameters may be serialized
using URI Query String Serialization.

(NOTE: Flows occur over TLS. Nonces are not shown).

## Lock Assertion Message

{: #satp-lock-assertion-message-sec}

The purpose of this message is for the client (sender gateway) to
convey a signed claim to the server (receiver gateway) declaring that the asset in
question has been locked or escrowed by the client in the origin
network (e.g. to prevent double spending).

The format of the claim is dependent on the network or system
of the client and is outside the scope of this specification.

This message is sent from the client to the Lock Assertion Endpoint at the server.

The server must validate the claims (payload)
in this message prior to the next step.

The message must be signed by the client.

The parameters of this message consists of the following:

- message_type REQUIRED urn:ietf:satp:msgtype:lock-assert-msg.

- session_id REQUIRED: A unique identifier (e.g. UUIDv2) chosen earlier
  by client in the Initialization Request Message.

- transferContext_id REQUIRED: A unique identifier (e.g. UUIDv2)
  used to identify the current transfer session at the application layer.

- lock_assertion_claim REQUIRED. The lock assertion claim or statement by the client.

- lock_assertion_claim_format REQUIRED. The format of the claim.

- lock_assertion_expiration REQUIRED. The duration of time of the lock or escrow upon the asset.

- hash_prev_message REQUIRED. The hash of the previous message.

- client_signature REQUIRED. The digital signature of the client.

## Lock Assertion Receipt Message

{: #satp-lock-assertion-receipt-section}
The purpose of this message is for the server (receiver gateway)
to indicate acceptance of the claim(s) in the lock-assertion message
delivered by the client (sender gateway) in the previous message.

This message is sent from the server to the Assertion Receipt Endpoint
at the client.

The message must be signed by the server.

The parameters of this message consists of the following:

- message_type REQUIRED urn:ietf:satp:msgtype:assertion-receipt-msg.

- session_id REQUIRED: A unique identifier (e.g. UUIDv2) chosen earlier
  by client in the Initialization Request Message.

- transferContext_id REQUIRED: A unique identifier (e.g. UUIDv2)
  used to identify the current transfer session at the application layer.

- hash_prev_message REQUIRED. The hash of previous message.

- server_signature REQUIRED. The digital signature of the server.

# Commitment Preparation and Finalization (Stage 3)

{: #satp-phase3-sec}
This section describes the transfer commitment agreement between the
client (sender gateway) and the server (receiver gateway).

This stage must be completed within the time specified
in the lock_assertion_expiration value in the lock-assertion message.

In the following, the sender gateway takes the role of the client
while the recipient gateway takes the role of the server.

The flow follows a request-response model.
The client makes a request (POST) to the Transfer Commitment endpoint at the server.

Gateways MUST support the use of the HTTP GET and POST methods
defined in RFC 2616 [RFC2616] for the endpoint.

Clients MAY use the HTTP GET or POST methods to send messages in this stage to the server.
If using the HTTP GET method, the request parameters maybe serialized
using URI Query String Serialization.

The client and server may be required to sign certain messages
in order to provide standalone proof (for non-repudiation) independent of the
secure channel between the client and server.
This proof maybe required for audit verifications post-event.

(NOTE: Flows occur over TLS. Nonces are not shown).

## Commit Preparation Message (Commit-Prepare)

{: #satp-commit-preparation-message-sec}
The purpose of this message is for the client to indicate
its readiness to begin the commitment of the transfer.

This message is sent from the client to the Commit Prepare Endpoint at the server.

The message must be signed by the client.

The parameters of this message consists of the following:

- message_type REQUIRED. It MUST be the value urn:ietf:satp:msgtype:commit-prepare-msg

- session_id REQUIRED: A unique identifier (e.g. UUIDv2) chosen earlier
  by client in the Initialization Request Message.

- transferContext_id REQUIRED: A unique identifier (e.g. UUIDv2)
  used to identify the current transfer session at the application layer.

- hash_prev_message REQUIRED. The hash of previous message.

- client_signature REQUIRED. The digital signature of the client.

## Commit Ready Message (Commit-Ready)

{: #satp-commit-ready-section}
The purpose The purpose of this message is for the server to indicate to the client that:
(i) the server has created (minted) an equivalent asset in the destination
network;
(ii) that the newly minted asset has been self-assigned to the server;
and (iii) that the server is ready to proceed to the next step.

This message is sent from the server to the Commit Ready Endpoint at the client.

The message must be signed by the server.

The parameters of this message consists of the following:

- message_type REQUIRED. It MUST be the value urn:ietf:satp:msgtype:commit-ready-msg.

- session_id REQUIRED: A unique identifier (e.g. UUIDv2) chosen earlier
  by client in the Initialization Request Message.

- transferContext_id REQUIRED: A unique identifier (e.g. UUIDv2)
  used to identify the current transfer session at the application layer.

- mint_assertion_claims REQUIRED. The mint assertion claim or statement by the server.

- mint_assertion_format OPTIONAL. The format of the assertion payload.

- hash_prev_message REQUIRED. The hash of previous message.

- server_signature REQUIRED. The digital signature of the server.

## Commit Final Assertion Message (Commit-Final)

{: #satp-commit-final-message-section}

The purpose of this message is for the client to indicate to the server
that the client (sender gateway) has completed the extinguishment (burn)
of the asset in the origin network.

The message must contain standalone claims related
to the extinguishment of the asset by the client.
The standalone claim must be signed by the client.

This message is sent from the client to the Commit Final Assertion Endpoint at the server.

The message must be signed by the server.

The parameters of this message consists of the following:

- message_type REQUIRED. It MUST be the value urn:ietf:satp:msgtype:commit-final-msg.

- session_id REQUIRED: A unique identifier (e.g. UUIDv2) chosen earlier
  by client in the Initialization Request Message.

- transferContext_id REQUIRED: A unique identifier (e.g. UUIDv2)
  used to identify the current transfer session at the application layer.

- burn_assertion_claim REQUIRED. The burn assertion signed claim or statement by the client.

- burn_assertion_claim_format OPTIONAL. The format of the claim.

- hash_prev_message REQUIRED. The hash of previous message.

- client_signature REQUIRED. The digital signature of the client.

## Commit-Final Acknowledgement Receipt Message (ACK-Final-Receipt)

{: #satp--final-ack-section}
The purpose of this message is to indicate to the client that the server has
completed the assignment of the newly minted asset to
the intended beneficiary at the destination network.

This message is sent from the server to the Commit Final Receipt Endpoint at the client.

The message must be signed by the server.

The parameters of this message consists of the following:

- message_type REQUIRED. It MUST be the value urn:ietf:satp:msgtype:ack-commit-final-msg.

- session_id REQUIRED: A unique identifier (e.g. UUIDv2) chosen earlier
  by client in the Initialization Request Message.

- transferContext_id REQUIRED: A unique identifier (e.g. UUIDv2)
  used to identify the current transfer session at the application layer.

- assignment_assertion_claim REQUIRED. The claim or statement by the server
  that the asset has been assigned by the server to the intended beneficiary.

- assignment_assertion_claim_format OPTIONAL. The format of the claim.

- hash_prev_message REQUIRED. The hash of previous message.

- server_signature REQUIRED. The digital signature of the server.

## Transfer Complete Message

{: #satp-transfer-complete-message-section}
The purpose of this message is for the client to indicate to the server that
the asset transer session (identified by session_id)
has been completed and that no further messages are to be
expected from the client in regards to this transfer instance.

The message closes the first message of Stage 2 (Transfer Commence Message).

This message is sent from the client to the Transfer Complete Endpoint at the server.

The message must be signed by the client.

The parameters of this message consists of the following:

- message_type REQUIRED. It MUST be the value urn:ietf:satp:msgtype:commit-transfer-complete-msg.

- session_id REQUIRED: A unique identifier (e.g. UUIDv2) chosen earlier
  by client in the Initialization Request Message.

- transferContext_id REQUIRED: A unique identifier (e.g. UUIDv2)
  used to identify the current transfer session at the application layer.

- hash_prev_message REQUIRED. The hash of previous message.

- hash_transfer_commence REQUIRED. The hash of the Transfer Commence message
  at the start of Stage 2.

- client_signature REQUIRED. The digital signature of the client.

# SATP Session Resumption

{: #satp-session-resume-section}
This section answers the question how can a backup gateway build trust
with the counter party gateway to resume the execution of the protocol,
in the presence of errors and crashes?

Gateways may enter faulty state at any time while execution the protocol.
The faulty state can manifest itself by incorrect behavior,
leading to gateways emitting alerts and errors.

In some instances, gateways may crash.
We employ either the primary-backup or self-healing paradigm,
meaning that the crashed gateway will eventually be replaced
by a functioning one, or recover, respectively.

When a crash occurs, we initiate a recovery procedure by
the backup gateway or the recovered gateway, as defined in the
crash recovery draft {{?I-D.draft-belchior-satp-gateway-recovery}}.
In either case, if the recovery happenswithin a time period defined as max_timeout (in Stage 2), the recovered gateway triggers a session resumption.
The schema and order of the recovered messages is specified in the crash recovery draft.

In the case where there is no answer from the gateway within the specified max_timeout,
the counter-party gateway rollbacks the process until that stage.
Upon recovery, the crashed gateway learns that the counterparty gateway
has initated a rollback, and it proceeds accordingly (by also initating a rollback).
Note that rollbacks can also happen in case of unresolved errors.

The non-crashed gateway that conducts the rollback tries to communicate
with the crashed gateway from time to time (self healing) or to contact
the backup gateways (primary-backup).
In any case, and upon the completion of a rollback,
the non-crashed gateway sends a ROLLBACK message
to the recovered gateway to notify that a rollback happened.
The recovered gateway should answer with ROLLBACK-ACK.

Since the self-healing recovery process does not require
changes to the protocol (since from the counterparty gateway perspective,
the sender gateway is just taking longer than normal;
there are no new actions done or logs recorded),
we focus on the primary-backup paradigm.

## Primary-Backup Session Resumption

{: #satp-session-resume-section-pb}

Upon a gateway recovering using primary-backup,
a new gateway (recovered gateway) takes over the crashed gateway.
The counter-party gateway assures that the recovered gateway
is legitimate (according to the crash recovery specification).

After the recovery, the gateways exchange information about
their current view of the protocol, since the crashed gateway
may have been in the middle of executing the protocol when it crashed.

After that, the gateways agree on the current state of the protocol.

## Recovery Messages

{: #satp-session-resume-recovery-msg}
We have omitted the logging procedure (only focusing the different messages).
As defined in the crash recovery draft {{?I-D.draft-belchior-satp-gateway-recovery}},
there are a set of messages that are exchanged between the recovered
gateway and counterparty gateway:

- RECOVER: when a gateway crashes and recovers,
  it sends a RECOVER message to the counterparty gateway,
  informing them of its most recent state.
  The message contains various parameters such as the session ID,
  message type, SATP stage, sequence number,
  a flag indicating if the sender is a backup gateway,
  the new public key if the sender is a backup,
  the timestamp of the last known log entry, and the sender's digital signature.

- RECOVER-UPDATE: Upon receiving the RECOVER message,
  the counterparty gateway sends a RECOVER-UPDATE message.
  This message carries the difference between the log entry
  corresponding to the received sequence number from the
  recovered gateway and the latest sequence number
  (corresponding to the latest log entry).
  The message includes parameters such as the session ID, message type,
  the hash of the previous message, the list of log messages that
  the recovered gateway needs to update, and the sender's digital signature.

- RECOVER-SUCCESS: The recovered gateway responds with
  a RECOVER-SUCCESS message if its logs have been successfully updated.
  If there are inconsistencies detected,
  the recovered gateway initiates a dispute with a RECOVER-DISPUTE message.
  The message parameters include session ID, message type,
  the hash of the previous message, a boolean indicating success,
  a list of hashes of log entries that were appended to the
  recovered gateway log, and the sender's digital signature.

In case the recovery procedure has failed and a rollback process
is needed, the following messages are used:

- ROLLBACK: A gateway that initiates a rollback sends a ROLLBACK message.
  The message parameters include session ID, message type,
  a boolean indicating success, a list of actions performed
  to rollback a state (e.g., UNLOCK, BURN), a list of proofs
  specific to the DLT [SATP], and the sender's digital signature.

- ROLLBACK-ACK: Upon successful rollback, the counterparty
  gateway sends a ROLLBACK-ACK message to the recovered gateway acknowledging
  that the rollback has been performed successfully.
  The message parameters are similar to those of the ROLLBACK message.

# Error Messages

{: #satp-alert-error-messages}
SATP SATP distinguishes between
application driven closures (terminations) and
those caused by errors at the SATP protocol level.

The list of errors and desciption can be found in the Appendix.

```
enum { session_closure(1), nonfatal_error (2) fatal_error(3), (255) } AlertLevel;

enum {
 close_notify(0),
 bad_certificate(42),
 unsupported_certificate(43),
 certificate_revoked(44),
 certificate_expired(45),
 certificate_unknown(46),
 illegal_parameter(47),
 TBD
 (255)
} AlertDescription;

struct {
 AlertLevel level;
 AlertDescription description;
} Alert;
```

{: #fig-error-format}

## Closure Alerts

{: #satp-closure-alerts-section}

The SATP client and server (gateways) must share knowledge that
the transfer connection is ending in order to avoid third party attacks.

(a) close_notify: This alert notifies the recipient that the sender gateway
will not send any more messages on this transfer connection.
Any data received after a closure alert has been received MUST be ignored.

(b) user_canceled: This alert notifies the recipient that the sender gateway
is canceling the transfer connection for some reason unrelated to a protocol failure.

## Error Alerts

{: #error-alerts-section}
When an error is detected by a SATP gateway, the detecting gateway sends a message to its peer.

Upon transmission or receipt of a fatal alert message, both gateways MUST immediately close the connection.
Whenever a SATP implementation encounters a fatal error condition,
it SHOULD send an appropriate fatal alert and
MUST close the connection without sending or receiving any additional data.

The following error alerts are defined:

- connection_error: There is an error in the TLS session establishment
  (TLS error codes should be reported-up to gateway level)

- bad_certificate: The gateway certificate was corrupt, contained signatures,
  that did not verify correctly, etc.
  (Some common TLS level errors: unsupported_certificate,
  certificate_revoked, certificate_expired, certificate_unknown, unknown_ca).

- protocol_version_error: The SATP protocol version the peer
  has attempted to negotiate is recognized but not supported.

- (Others TBD)

# Security Consideration

{: #satp-Security-Consideration}
Gateways are of particular interest to attackers because
they are a kind of end-to-end pipeline that enable the transferral of
digital assets to external networks or systems.
Thus, attacking a gateway may be attractive to attackers instead of
the network behind a gateway.

As such, hardware hardening technologies and
tamper-resistant crypto-processors (e.g. TPM, Secure Enclaves, SGX)
should be considered for implementations of gateways.

# IANA Consideration

{: #satp-iana-Consideration}

(TBD)

# Appendix: Error Types

{: #error-types-section}
The following lists the error associated with each message in SATP.

(Note: these have been laid out for convenience, and may be grouped together more efficiently later).

## Transfer Commence and Response errors

{: #errors-transfer-commence}

The following are the list of errors related to Transfer Commence and Response:

- err_2.1: Badly formed message.
- err_2.2: Incorrect parameter.
- err_2.3: ACK mismatch.

## Lock Assertion errors

{: #errors-lock-assertion}
The following are the list of errors related to Lock Assertion:

- err_2.4.1: Badly formed message: badly formed Claim.
- err_2.4.2: Badly formed message: bad signature.
- err_2.4.3: Badly formed message: wrong transaction ID.
- err_2.4.4: Badly formed message: Mismatch hash values.
- err_2.4.5: Expired signing-key certificate.
- err_2.4.6: Expired Claim.

## Lock Assertion Receipt errors

{: #errors-lock-assertion-receipt}
The following are the list of errors related to Lock Assertion Receipt:

- err_2.6.1: Badly formed message: badly formed Claim.
- err_2.6.2: Badly formed message: bad signature.
- err_2.6.3: Badly formed message: wrong transaction ID.
- err_2.6.4: Badly formed message: Mismatch hash values.
- err_2.6.5: Expired signing-key certificate.
- err_2.6.6: Expired Claim.

## Commit Preparation errors

{: #errors-commit-prepare}
The following are the list of errors related to Commit Preparation:

- err_3.1.1: Badly formed message: wrong transaction ID.

- err_3.1.2: Badly formed message: mismatch hash value (i.e. from msg 2.6).

- err_3.1.3: Incorrect parameter.

- err_3.1.4: Message out of sequence.

## Commit Preparation Acknowledgement errors

{: #errors-commit-prepare-ack}

The following are the list of errors related to Commit Preparation Acknowledgement:

- err_3.2.1: Badly formed message: wrong transaction ID.
- err_3.2.2: Badly formed message: mismatch hash value.
- err_3.2.3: Incorrect parameter.
- err_3.2.4: Message out of sequence.

## Commit Ready errors

{: #errors-commit-ready}

The following are the list of errors related to Commit Ready:

- err_3.4.1: Badly formed message: wrong transaction ID.

- err_3.4.2: Badly formed message: mismatch hash value.

- err_3.4.3: Incorrect parameter.

- err_3.4.4: Message out of sequence (ACK mismatch).

## Commit Final Assertion errors

{: #errors-commit-final-assertion}

The following are the list of errors related to Commit Final Assertion:

- err_3.6.1: Badly formed message: badly formed Claim.

- err_3.6.2: Badly formed message: bad signature.

- err_3.6.3: Badly formed message: wrong transaction ID.

- err_3.6.4: Badly formed message: Mismatch hash values.

- err_3.6.5: Expired signing-key certificate.

- err_3.6.6: Expired Claim.

--- back
