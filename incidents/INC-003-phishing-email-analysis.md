# INC-003: Phishing Email Analysis — Bank Credential Theft (Bradesco/Livelo)

> **Training analysis.** The email examined here is a real phishing sample from the public [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) research dataset (file `email/sample-1.eml`). It was analysed in a safe, isolated way — headers and decoded body only, no links opened. All malicious URLs below are **defanged** (`hxxp`, `[.]`).

| Field | Value |
|---|---|
| **Incident ID** | INC-003 |
| **Type** | Phishing email (credential harvesting) |
| **Severity** | High (would-be credential theft) |
| **Status** | Closed |
| **Verdict** | Confirmed phishing, high confidence |
| **Email date** | 2023-09-19 18:36 UTC |
| **Analysed** | 2026-11-18 |
| **Source** | Public dataset — Phishing Pot, `sample-1.eml` |
| **Analyst** | Krish Patel |

---

## 1. Executive Summary

An email impersonating a Brazilian bank (**Banco Bradesco / Livelo rewards**) claimed the recipient had 92,990 reward points "expiring today" and urged them to click a button to redeem. The message is phishing: its goal was to lure the victim to a fake website and steal their banking login.

Analysis of the email's headers shows the sender was faked. The message did not come from the bank — it was sent as the `root` user from a rented DigitalOcean cloud server, and it failed every email-authentication check (SPF, DKIM, DMARC). Microsoft's own filter had already scored it as spam. The "redeem" button pointed to an unrelated, random `.me` domain, not the bank.

No action was required on a live system (this is a captured sample), but the report documents the indicators and the defences that stop this class of attack.

## 2. The Email

| Header | Value |
|---|---|
| **Subject** | `CLIENTE PRIME - BRADESCO LIVELO: Seu cartão tem 92.990 pontos LIVELO expirando hoje!` ("…points expiring today!") |
| **From** | `BANCO DO BRADESCO LIVELO <banco.bradesco@atendimento.com.br>` |
| **Return-Path** | `root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` |
| **Sender IP** | `137.184.34.4` |
| **Date** | Tue, 19 Sep 2023 18:36 UTC |

**Body (translated gist):** "You have Livelo points on your Bradesco card that **expire TODAY** — redeem now to avoid losing them. **92,990 points expire today.** [Redeem Now]. Trade points for air miles, up to 35% off your bill."

**Link behind the "Redeem Now" button (defanged):** `hxxps://blog1seguimentmydomaine2bra[.]me/`
(Two other links in the HTML were Google Fonts — `fonts.googleapis.com`, `fonts.gstatic.com` — benign styling.)

## 3. Analysis

### 3.1 The sender is faked (From vs Return-Path)
The friendly **From** address (`banco.bradesco@atendimento.com.br`) is set by the sender and is easily forged. The **Return-Path**, set by the sending mail server, reads `root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`. These do not match. The mail was actually sent by the `root` account on a server named like a default **DigitalOcean** droplet (`...sfo3-06`, their San Francisco region), not by any bank system.

### 3.2 The true origin (Received chain)
Reading the `Received:` headers from the bottom up, the message originated at:

```
from ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 (137.184.34.4)
by  ...protection.outlook.com
by  ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 (Postfix, from userid 0)
```

`Postfix, from userid 0` confirms it was sent by **root (uid 0)** on a Linux box. Banks do not send customer mail as root from a disposable cloud VPS.

### 3.3 Authentication failed on every check
From the `Authentication-Results` header:

| Check | Result | Meaning |
|---|---|---|
| **SPF** | `temperror` (sender IP 137.184.34.4) | Could not confirm the server is authorised to send for the domain |
| **DKIM** | `none` (message not signed) | No cryptographic signature at all |
| **DMARC** | `temperror`, `compauth=fail reason=001` | Overall authentication failed |
| **Microsoft SCL** | `5` | Microsoft already classified the message as spam |

A genuine bank email passes SPF, DKIM and DMARC cleanly. This one passed none.

### 3.4 Social engineering
- **Urgency / loss aversion:** "expiring **today**," "redeem **now** before they expire."
- **Authority / impersonation:** a trusted bank (Bradesco) and premium card (Visa Infinite).
- **Reward bait:** 92,990 points, up to 35% off.
- **Single call-to-action button** hiding the real destination URL.

### 3.5 The payload
The button links to `hxxps://blog1seguimentmydomaine2bra[.]me/` — a random, meaningless `.me` domain with no connection to Bradesco or Livelo. This is the credential-harvesting page the victim was meant to reach and enter their banking login into.

## 4. Enrichment

| IOC | Service | Result |
|---|---|---|
| IP `137.184.34.4` | ipinfo.io | **AS14061 DigitalOcean, LLC**, Santa Clara, California, US — a cloud-hosting provider, confirming a rented VPS rather than bank infrastructure |
| IP `137.184.34.4` | AbuseIPDB / VirusTotal | **Recommended follow-up** — look up the IP reputation (abuse reports, vendor detections). These services require a free account/API key for automated queries |
| URL `blog1seguimentmydomaine2bra[.]me` | VirusTotal / URLhaus | **Recommended follow-up** — submit the URL for vendor verdicts and malware/phishing-URL listing |

The IP enrichment independently confirms the header analysis: the sender is a commodity cloud server, not a bank. Full reputation enrichment via VirusTotal/AbuseIPDB is the documented next step; those services block anonymous scraping by design, so they are queried with a registered API key (the task this portfolio's IOC-enrichment tool automates).

## 5. Indicators of Compromise (defanged)

| Type | Value |
|---|---|
| Sender IP | `137.184.34.4` (DigitalOcean, AS14061) |
| Sending host | `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` |
| Spoofed From | `banco.bradesco@atendimento.com.br` |
| Phishing URL | `hxxps://blog1seguimentmydomaine2bra[.]me/` |
| Phishing domain | `blog1seguimentmydomaine2bra[.]me` |
| Subject lure | `CLIENTE PRIME - BRADESCO LIVELO: ... 92.990 pontos LIVELO expirando hoje!` |

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | Observed |
|---|---|---|
| Initial Access | T1566.002 Phishing: Spearphishing Link | Email with a link to a credential-harvesting site |
| Resource Development | T1583.001 Acquire Infrastructure: Domains | Attacker-registered `.me` domain |
| Resource Development | T1583.003 Acquire Infrastructure: Virtual Private Server | Sent from a rented DigitalOcean VPS |
| Defense Evasion | T1036 Masquerading | Impersonation of a trusted bank brand |

## 7. Response and Recommendations

Because this is a captured training sample, no live remediation was needed. In a real environment the response and defences would be:

**Immediate response**
- Do not click; report the email to the security team / abuse mailbox.
- Block the phishing domain and URL at the mail gateway and web proxy.
- Search mail logs for other recipients of the same subject/sender and quarantine those copies.
- If anyone clicked and entered credentials, force a password reset and watch that account for misuse.

**Preventive controls**
- Enforce inbound **SPF/DKIM/DMARC** checking and reject or quarantine failures. This email failed all three and would be stopped by a strict DMARC policy.
- Keep spam/phishing filtering tuned (Microsoft had already scored this SCL 5).
- **User awareness training** on the exact tells seen here: urgency, reward bait, and hovering a link to see its real destination before clicking.
- Add the IOCs above to blocklists and threat-intel feeds.

## 8. Lessons Learned
- **The headers tell the truth even when the body lies.** The visible "From" said bank; the Return-Path, Received chain and authentication results all said "root on a rented cloud server."
- **A failed SPF/DKIM/DMARC trio plus a mismatched Return-Path is a near-certain phishing signal** — fast to check and hard to fake.
- **Analyse safely:** read headers and decode the body; never open the link. Enrich IOCs through intel services, not by visiting them.
