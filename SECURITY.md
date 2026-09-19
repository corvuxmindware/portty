# Security policy

Portty lets a paired phone watch and control real shells on a real machine, and
approve actions taken by coding agents running as you. A flaw here is not a
cosmetic bug. We take reports seriously and we would rather hear about a
suspicion than miss a real problem.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion.**

Use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/corvuxmindware/portty/security)
   of this repository.
2. Choose **Report a vulnerability**.
3. Fill in the form.

The report stays private between you and the maintainers until a fix is ready.

### What to include

- What an attacker gains, in one sentence.
- The versions or commit you tested.
- Your platform: host OS, phone OS, and app version if relevant.
- Steps to reproduce, ideally the smallest case that shows the problem.
- Any proof-of-concept code or captured traffic.

**Redact secrets before you send them.** Pairing tickets, pairing phrases,
identity keys, reconnect tokens, and push credentials are live keys to a
machine. We do not need a working one to understand your report.

## What we will do

- We aim to acknowledge a report within **3 working days**.
- We aim to give you an initial assessment - whether we can reproduce it, and how
  serious we think it is - within **10 working days**.
- We will keep you updated while we work on a fix.
- We will tell you before we publish anything, and we will credit you by the name
  you choose unless you prefer to stay anonymous.

Portty is maintained by a small team. If you have not heard back within those
windows, please file a second private report saying so rather than going public.

## Disclosure

We ask for **90 days** from your first report before public disclosure, or until
a fix ships, whichever comes first. If a flaw is being actively exploited, tell
us and we will move faster.

## Supported versions

Portty is pre-1.0 and moves quickly. Only the latest published release and the
current `main` branch receive security fixes. There are no backports to older
versions.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| `main` | Yes |
| Anything older | No |

## In scope

- The `portty` CLI and the `portty-host` daemon.
- The mobile app under `app/`.
- The optional self-hosted `portty-push-relay`.
- The pairing, revocation, and reconnect flows.
- The ACP agent permission path, including anything that lets a paired phone
  cause an action the approval card did not describe.
- Packaging and service files under `packaging/` that would install Portty
  insecurely.

## Out of scope

These are known properties of the design, documented in the
[security model](README.md#security-model-and-operational-guidance). Reporting
them is not a vulnerability:

- **A paired phone is trusted.** Pairing is a deliberate act that hands over
  control of the machine. Anyone holding a pairing ticket, phrase, or QR code has
  a complete key - that is the design, not a bug.
- **Agents run unsandboxed as you.** Portty intercepts and surfaces permission
  requests; it is not a sandbox. What an approved action then does is the agent's
  business.
- **The operation category on an approval card is self-reported** by the ACP
  adapter. A lying adapter is outside Portty's trust boundary.
- **The push relay sees network metadata** - source IP, a random host handle, the
  device token, and wake timing. This boundary is documented in
  [packaging/PUSH-SETUP.md](packaging/PUSH-SETUP.md).
- Anything requiring an attacker who already has local access as your user on the
  host.
- Findings from automated scanners with no demonstrated impact.
- Missing hardening headers or best-practice warnings with no attack behind them.

If you are unsure whether something is in scope, report it privately and let us
decide.

## Please do not

- Test against machines or accounts you do not own.
- Run denial-of-service tests against anyone else's host or relay.
- Access, alter, or keep data that is not yours.
- Use social engineering against the maintainers or users.

Research carried out in good faith and within this policy will not lead to legal
action from Corvux Mindware Private Limited.
