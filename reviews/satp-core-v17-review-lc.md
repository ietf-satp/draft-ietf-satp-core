# SATP Core (-17) Last-Call Review — Reviewer Feedback

Reviewer feedback received during IETF Last Call on `draft-ietf-satp-core-17` (LC ended 2026-10-09).


| Reviewer | Role | Verdict | Date |
|---|---|---|---|
| Kyle Rose | TSVART | Not Ready | 2026-10-04 |
| Joel Halpern | GEN-ART | On the Right Track | 2026-10-05 |
| David Dong | IANA (ticket #1460479) | Review ok; 1 question | 2026-10-09 |
| Ionuț Mihalcea | SECDIR | Not Ready | 2026-10-16 |

---

# 1. Kyle Rose — TSVART

- **Subject:** [Sat] draft-ietf-satp-core-17 ietf last call Tsvart review
- **Review result:** Not Ready
- **Archive:** <https://mailarchive.ietf.org/arch/msg/sat/dBzecDU_LYm607PZPLnPjv4MEXM/>

## Review (verbatim)

Document: draft-ietf-satp-core
Title: Secure Asset Transfer Protocol (SATP) Core
Reviewer: Kyle Rose
Review result: Not Ready

This document has been reviewed as part of the transport area review team's
ongoing effort to review key IETF documents. These comments were written
primarily for the transport area directors, but are copied to the document's
authors and WG to allow them to address any issues raised and also to the IETF
discussion list for information.

When done at the time of IETF Last Call, the authors should consider this
review as part of the last-call comments they receive. Please always CC
tsv-art@ietf.org if you reply to or forward this review.

This document is Not Ready.

- It's entirely unclear to me why the acceptable TLS parameters are not simply
  regarded as a black box to this protocol. Adding a separate validation step
  instead of preconfiguring the TLS stack with the appropriate parameters and
  relying on it to do the right thing seems like unnecessary complexity.

- The protocol uses HTTP POSTs under the covers, but (to cite just two
  examples) does not define (a) what headers might or might not be present, if
  any, or for what purpose; or (b) what an acceptable response to a POST is.

- The gateway-to-gateway protocol uses HTTP under the covers for
  request/response, but only in the most trivial sense: it sounds from section
  8.7 that the actual high-level protocol flow is each gateway POSTing to the
  other with a trivial and/or boolean response, which may come with (both
  obvious and non-obvious) operational complications with respect to
  discoverability, firewalls, and NATing, none of which are explored here.

- There is sufficient ambiguity in the use of client (app or sending gateway?)
  and server (GW1 or GW2?) that I have to guess at what is intended. At several
  points, there are statements of the form "This message is sent from the server
  to the such-and-such endpoint at the client", which blows my mind based on the
  mental model that a client/server architecture involves the client reaching
  out to the server at a pre-established rendezvous point, not the other way
  around, and that endpoints in HTTP APIs are typically URLs/paths. In one
  place, the draft states "Servers MUST support the use of the HTTPS POST
  method for the endpoint". Stipulated; but then what about when the server is
  (I think?) POSTing a message to a client? "Clients MUST support..."? At the
  very least, cleaning up the terminology here would improve comprehensibility.

- HTTP implementations over real networks have behaviors that may interfere
  with the correctness properties this protocol is trying to achieve. As a
  fellow IETFer said some years ago, "The web doesn't work without retries."
  What happens if someone tries to implement this protocol atop an HTTP
  library that silently retries POSTs on some classes of network failure? It
  might help to expand the security considerations section to systematically
  walk through all the possible failure modes at various stages of the
  protocol, and then to draw lines from those failure modes to various network-
  and transport-related issues that might trigger them.

- More generally, I'm skeptical that HTTP is the right substrate for something
  that is a natural fit for an RPC protocol. With HTTP, you have to deal with a
  ton of complexity from the messy history of web protocol evolution without
  ever wanting to leverage any of it. I'm all for not building a custom tool
  for every single job, but there is some level of complexity below which the
  overhead of dealing with the giant convoluted gun with a hundred buttons, one
  of which is "fire" and another of which is "reverse barrel", is far too
  costly and/or risky.

- Has there been any attempt to independently produce multiple interoperating
  implementations of this protocol? The draft doesn't seem concrete enough for
  that: too many details are left unspecified.

As a final note, I'm glad I'm reviewing this for transport issues, not
security issues. For instance:

- What does "at least as secure as TLS_AES_128_GCM_SHA256" mean?

- What about groups and acceptable certificate signature algorithms? Both
  are critical elements of the confidentiality guarantees provided by TLS.
  Either be redundantly prescriptive about all of it, or black box all of it.

- The security considerations section should probably reference a library
  of research into the pitfalls of distributed consensus, even under the
  assumption that all participants are honest. There are a ton of potential
  failure cases (e.g., network partitions and indefinitely delayed messages)
  that need a well-defined disposition allowing a third-party observer (e.g.,
  the legal system) to construct some consistent descendant state. It seems
  like the use cases for which this protocol has been designed should have
  such a property as a core requirement if it is to be useful.

## Follow-up replies from the reviewer (verbatim)

Kyle Rose, reply 1 — Mon, 05 October 2026 14:49 UTC
<https://mailarchive.ietf.org/arch/msg/sat/S0DA-lbuGN2s8Dpl2qAtVMLQYhw/>

> With the stipulation that I know basically nothing about what you are trying
> to achieve beyond what I've read during the review, this sounds right. Since
> the protocol is not readily implementable as-is from just the existing spec
> (since there are gaps that need to be filled in, like HTTP endpoints), it
> might be better to describe it as a JSON message-based protocol under some
> given assumptions about the substrate, but with all the transport details
> left as an exercise to a future spec or to individual implementations. Then,
> the document can focus on a systemic analysis of the potential failure modes
> at a higher level of abstraction (e.g., "What if message X is lost or delayed
> indefinitely?"), which I suspect already exist as durable informative
> references to research analysis in this area.
>
> To minimize duplication of effort, and to minimize distractions for
> implementors who go into this exercise accepting the known risks, you may
> want to limit the security discussion in the draft to your implied threat
> model (gateways/clients/ledgers are trusted ⇒ threats are all third parties)
> and only highlight those vulnerabilities that such a third party could
> exploit to disrupt (delay, prevent, etc.) settlement in some way.
>
> Both changes I think would make the document cleaner, easier to read and
> comprehend, and would allow you to work at a level of abstraction that makes
> crystal clear to the reader that there are implementation details to be
> filled in, but without constraining implementors beyond what is minimally
> required to achieve the ACID guarantees. Maintaining clear separation of
> layers in the protocol design will make everyone's lives easier.

Kyle Rose, reply 2 — Mon, 05 October 2026 23:04 UTC
<https://mailarchive.ietf.org/arch/msg/sat/ubJlrKO5LjkWNtQVJ0sygOqtWrM/>
(in reply to: "Could we specify that SATP-Core must run over TLS1.3 and just stop there (without requiring HTTP)? Is that acceptable for an IETF RFC document?")

> I think once you are specifying TLS (or any other transport-layer security
> protocol by name) instead of stating the properties your specific business
> logic requires from the communication channel, you are necessarily in the
> business of prescribing a complete protocol stack. I think this is both too
> complex and too constraining, given some of the other replies on this
> thread.
>
> I think it's going to be easier to make sense of a draft describing a
> pseudo-wire image protocol for your business logic atop a transport
> abstraction satisfying some set of requirements around
> confidentiality/integrity/authenticity/privacy/non-replayability/etc,
> leaving the details for mapping your protocol to a given transport stack to
> a future draft or to experimental implementations.

---

# 2. Joel Halpern — GEN-ART

- **Subject:** [Sat] draft-ietf-satp-core-17 ietf last call Genart review
- **Review result:** On the Right Track
- **Archive:** <https://mailarchive.ietf.org/arch/msg/sat/zBx3PRyDGL7L3RD8bNhmcpevM74/>

## Review (verbatim)

I am the assigned Gen-ART reviewer for this draft. The General Area
Review Team (Gen-ART) reviews all IETF documents being processed
by the IESG for the IETF Chair.  Please treat these comments just
like any other last call comments.

For more information, please see the FAQ at
<https://wiki.ietf.org/en/group/gen/GenArtFAQ>.

Document: draft-ietf-satp-core-17
Reviewer: Joel Halpern
Review Date: 2026-10-05
IETF LC End Date: 2026-10-09
IESG Telechat date: Not scheduled for a telechat

Summary:
This document is quite readable and mostly in good shape.  There are a few major
issues that need to be addressed before publication as a Proposed
Standard RFC, as
well as some minor items whose evaluation I would appreciate.

Major issues:

   For obvious reasons, the protocol requires that the assert networks on each
   end have certain capabilities.  I think it would help the document's
   clarity significantly if there were a separate section enumerating those required
   capabilities. For example I believe that an asset network
   supporting SATP needs to support locking and burning of digital assets.  I
   presume such a call-out was omitted because it was obvious to those
   actively working in the space.

   The lock mechanism descriptions seem slightly inconsistent.  Section 5.3.15
   on Asset Lock Mechanism within a Network describes three common mechanisms,
   but does not say these are requried.  In fact, the section says that what
   the two sides support may be different.  Which made sense when I read it.
   But then I got to section 8.1 on the Stage one messaging, bullet 3 is the
   networkLockType, it is required, and it has a list of exactly three values
   which are permitted.  I am having trouble understanding how these two
   sections are consistent.  (Section 8.2 at least notes that future versions
   may expand the list.  But I still wonder about the relationship to 5.3.15
   which seems to say it is a local matter.)

   Section 9.1 on the Lock Assertion Messages states "The format of the claim
   is dependent on the network or system of the client and is outside the
   scope of this specification."  I can't find anything why negotiates or
   communicates this format in advance so that the two parties can know
   whether the server will understand the clients lock assertion?  Or is there
   for some reason no need for the server to understand this?  In which case
   that itself requires explanation in this document. I am not sure I have
   gotten this right, but there appears to be a potential race condition.
   What if the TCP and TSL session terminates after the client sends the
   Commit Final Assertion Message (Commit-Final)?  The asset has been removed
   on the sending side, but the server might or might not have been told to go
   ahead and finalize the created object?  This seems related to the old TCP
   fin race problem of knowing when both sides have really communicated
   everything.  (I hope I am simply missing something here.)  This seems
   related to the next-to-last paragraph in section 11.5 (part of the error
   handling) which says that in the state I am trying to describe, the abort
   can't unwind the deletion.  It does not seem to say what is supposed to
   happen on the server side to fix things?

Minor issues:

   I wonder if readers would be helped by a subsection in section 4 of
   something like "security behavioral goals"?  I found in reading section 5
   that I was wondering why there was a need for a message digital signature
   (5.2) beyond the integirty and authentication provided by TLS 1.3.  And
   similarly, why there was a need for a Payload Hash.

   It is unclear whether network locks are required to have a timeout.  In
   section 8.1 the timeout is optional, depending upon the lock type.  In
   section 8.2 the timeout is required independent of the lock type? Is there
   an implicit requirement that a client may only be engaging in one transfer
   request over a single session (single TLS connection with a single
   sessionID)?  I think that is the intention, but I missed the text that
   said so.

   This single threading assumption then leads to the question of why several
   of the messages have hashes of the earlier messages from the same session.
   It may be that an answer to the major issue on general security behavioral
   assumptions above will explain why these are needed.

   In the transition between section 8.6 and 8.7 on the transfer initiation
   messages, is there any circumstance other than a malformed message that
   could prevent or delay the sending of the Commence Response Message
   (ACK-Commence)?  If not, what value does the message have?

   Section 9.1 on the Lock Assertion Message says that "This message is sent
   from the client to the Lock Assertion Endpoint at the server."  However, it
   is sent over the same TLS connection that was used in stage-1.  And uses
   the same Session ID.  So it appears that it is sent to the same party that
   the stage-1 messages are sent to.  In what sense is it sent to the Lock
   Assertion Endpoint at the server?  A similar question applies to references
   to the Commit Prepare Endpoint in section 10.1

   There seems to be a general protocol design issue possibly related to
   attempting to tie the messages more explicitly to the stage transitions.
   For example, it is not obvious why one needs all four of "I have locked"
   "Ack that you have Locked"  Please prepare to Commit" and "I have prepared
   to commit" when the sequence "I have locked" responded to with "I have
   prepared to commit" would result in fewer messages with the same properties
   and effective transitions.  As a reader, there seem to be more messages
   than are needed.  If the underlying connection were unreliable, then the
   additional messages would be more important.  But it is a TLS connection.

Nits/editorial comments:

   In section 5.3.1 on Protocol Version, the second sentence includes
   "Implementations not understanding a future option value should..."  I
   presume this means not understanding a future Protocol Version, and the
   reference to "option" is a cut-and-paste artifact?

   I wonder if it would be helpful to readers to include an explanation or
   citation as to why RATS [RFC9334] attestation is required in section 7.

---

# 3. David Dong — IANA

- **From:** David Dong via RT `<drafts-lastcall@iana.org>`
- **Ticket:** IANA #1460479
- **Date:** 2026-10-09

## Email (verbatim)

> IESG/Authors/WG Chairs:
>
> IANA has completed its review of draft-ietf-satp-core-17. If any part of this review is inaccurate, please let us know.
>
> IANA has a question about one of the actions requested in the IANA Considerations section of this document.
>
> IANA understands that, upon approval of this document, there are two actions that we must complete.
>
> First, in section 13.1 of the current draft, the document requests the registration of a URN.
>
> IANA Question --> Could the authors specify in which IANA URN registry they would like the registration to be made?
>
> Second, in the applications namespace of the Media Types registry located at:
>
> https://www.iana.org/assignments/media-types
>
> a single registration is to be made as follows:
>
> Name: satp+json
> Template: [ TBD-at-registration ]
> Reference: [ RFC-to-be ]
>
> We understand that these are the only actions required to be completed upon approval of this document.
>
> NOTE: The actions requested in this document will not be completed until the document has been approved for publication as an RFC. This message is meant only to confirm the list of actions that will be performed.
>
> For definitions of IANA review states, please see:
>
> https://datatracker.ietf.org/help/state/draft/iana-review
>
> Thank you,
>
> David Dong
> IANA Services Sr. Specialist

---

# 4. Ionuț Mihalcea — SECDIR

- **Review:** IETF Last Call review of `draft-ietf-satp-core-17`
- **Review result:** Not Ready
- **Completed:** 2026-10-16
- **Datatracker:** <https://datatracker.ietf.org/doc/review-ietf-satp-core-17-secdir-lc-mihalcea-2026-10-16/>
- **Archive:** <https://mailarchive.ietf.org/arch/msg/secdir/Iyn6htsn60clvTpI55cTszQiQlQ>

## Review (verbatim)

Reviewer: Ionuț Mihalcea
Review result: Not Ready

Hello,

I have completed my SECDIR review of draft-ietf-satp-core-17. My result is Not
Ready, as some security-relevant issues need to be addressed before the draft
can proceed. I'll split my comments into three categories: security bindings,
2PC semantics, transport/HTTP and finally some other comments. Note that I am
not a transport expert, so while I do mention some transport/HTTP issues, I
won't be treating them in as much depth as the first two categories.

Security bindings

One aspect that I think is underdefined in the current document is the
security binding between gateway public keys and network assets. Specifically,
the draft relies on gateway keys being certified to deliver non-repudiation
guarantees (e.g., "signatures provide audit and non-repudiation evidence",
Section 1), but, as far as I can tell, never states what it is that gateway
keys are actually certified against. If a gateway key is certified against an
ephemeral endpoint identity, then the non-repudiation guarantees that the
protocol assumes may be weaker than expected.

Additionally, the draft assumes that message authentication provided by the
underlying secure channel matches the actor that signed the JWS signature
carried in the message payload. If this is not the case, then an unauthorized
intermediary could relay unsigned messages, violating protocol assumptions.
Moreover, this is a stronger assumption than merely requiring the use of TLS,
so, to the extent that it is assumed, I think it should be explicitly
mentioned as an assumption in the Security Considerations, along with an
analysis of what happens if this assumption does not hold.

Finally, the gateways can relay attestation information from Stage 0 [arch].
It is not clear to me how this information should be treated in the protocol.
Given that attestation comes from a separate domain, one potential approach
could be to simply define the attestation payload as opaque, and require
gateways to relay it to their local policy engines, which would interpret it
in the context of local policy.

2PC semantics

As a general note, the 2PC protocol defined in Section 8 is quite clear. My
concerns are mostly related to scenarios where the two parties end up in
disagreement about the state of the transaction, leading to inconsistent
outcomes.

My main concern, here, is that certain paths in the protocol allow aborting a
transaction after the prepare stage, or even after the burn operation, in ways
that can lead to permanent asset loss on one side while the other side may
hold inconsistent state. In my reading:

* After Commit-Prepare, the sender can abort while the receiver may have
already partially progressed towards mint.
* After Commit-Final, the sender side asset is burned, but if the final
acknowledgement is not received, there is no defined recovery path: the
sender believes failure, while the receiver may complete mint, leading to
permanent loss or double-spend across networks.

Once the receiver has prepared, aborting via a simple Abort message can lead
to permanent asset loss, as the lock may expire without the sender having any
evidence of the receiver's state. Relatedly, once a lock is placed and the
receiver does not respond, the sender has no safe recovery path: aborting
risks asset loss, while not aborting leaves the lock and timeout to expire.
Depending on the network, this may be equivalent to loss of the asset.

I would strongly encourage the authors to specify which state transitions are
permissible and which are not, and, in particular, which states are terminal
and what evidence must be retained in each. Specifically, I suggest clearly
marking the states after which abort is no longer permissible, and adding an
explicit recovery or reconciliation procedure covering the case where the
sender misses the final acknowledgement.

Additionally, while the protocol defines a timeout for locks, it does not
appear to clearly distinguish between timeout as a safety mechanism and
timeout as a liveness mechanism. If a receiver is honest but slow, timeout
expiry can cause asset loss. It would be good to explicitly address this
tension, even if the resolution is left to a future recovery specification.

Finally, the inner claims of some messages are not always bound to the outer
claim. If these inner claims are not cryptographically bound to the outer
claim, then there is a potential for replay of inner claims across
transactions, which could lead to an attacker being able to claim assets on
the target network by replaying a payload from a previous transaction that
was, e.g., legitimately requested by an honest party. I believe this could be
resolved by ensuring that every inner claim is signed by the same key as the
outer claim and includes the session identifier and outer claim hash in its
payload, or equivalent mechanisms.

Transport/HTTP

I agree with the reviewer comments regarding the transport/HTTP layer. In
short, the document should either fully specify HTTP semantics (headers,
response codes, error formats, etc.) or remain transport-agnostic and defer
those to a separate binding document. I also agree with other reviewers that
the client/server terminology needs clarifying, as it is currently ambiguous
whether it refers to application↔gateway or gateway↔gateway.

Other comments

* Section 5.4.4: the draft relies on JWS but does not specify an allowlist of
acceptable JWA algorithms. Without one, an implementation might accept
algorithms that are not appropriate (e.g., "none" or symmetric algorithms in
asymmetric contexts), leading to downgrade or substitution issues. I
recommend adding an allowlist (e.g., EdDSA, ES256, RS256, or any of the
algorithms that are deemed suitable), potentially aligned with COSE/JOSE
current guidance.
* Section 5.3.5: it would be useful to state that URIs in the problem details
must be absolute or must follow specific encoding rules, to avoid ambiguity.
* It may be useful to consider requiring canonical JSON serialization for
hashing purposes, or at least pointing to RFC 8785.
* Section 8.4, first bullet: It is not clear to me what "the hash-chain of
the current session is reset" means here, since the rest of the document
seems to rely on an unbroken hash-chain from session establishment. Could
the authors clarify whether this is meant to reset an application-level
hash-chain, and, if so, why the break does not affect the evidence chain?

Nits

* IANA: The "RSA" identifier used in the draft is ambiguous (RSA PKCS#1 v1.5
or RSASSA-PSS?). If it's PKCS#1 v1.5, I would suggest using the standard
JWA identifier RS256; if it's RSASSA-PSS, then PS256.
* The message named ack-prepare-msg appears to be a negative acknowledgement
for the Commit-Prepare message (referred to as commit-ready-msg elsewhere in
the draft). The naming is confusing, perhaps worth revisiting.
* gatewayAndNetworkCapabilities.gatewayTlsScheme appears to conflate two
distinct concerns (TLS and application-level signing), the draft might
benefit from clarifying or splitting that field.

As a final note, I want to say that I really enjoyed reading the document and
that I think this is a very useful protocol, and that the current state is
close to being ready, but the 2PC edge cases and the security bindings need
more attention.

[arch] https://datatracker.ietf.org/doc/draft-ietf-satp-architecture/
[arch-review]
https://datatracker.ietf.org/doc/review-ietf-satp-architecture-10-genart-lc-rosseau-2026-10-16/
[SEAT WG] https://datatracker.ietf.org/wg/seat/about/
