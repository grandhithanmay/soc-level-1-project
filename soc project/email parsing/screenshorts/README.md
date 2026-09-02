🛡️ PHISHING EMAIL CAMPAIGN DETECTION & INVESTIGATION

SOC L1 Investigation | Splunk | Email Security Gateway Logs

================================================================

01. INVESTIGATION OVERVIEW

Objective

Detect and investigate suspicious inbound email activity by identifying:
- Emails failing SPF, DKIM, and DMARC authentication
- Sender domains using typosquatting/homoglyph spoofing techniques
- Repeated attempts from the same sender targeting multiple recipients
- Reply-To address mismatches indicating spoofing
- Confirmed user interaction (clicked links or opened attachments)
- Malicious attachments disguised with double file extensions

Tools Used
- SIEM: Splunk Enterprise 10.4.2
- Log Source: Email Security Gateway Logs (CSV)
- Query Language: SPL
- Investigation Level: SOC L1

================================================================

02. INVESTIGATION SUMMARY

Sender (Primary): accounts@paypa1-secure-billing.com
Source IP: 91.108.56.23
Recipients Targeted: 3
Authentication Result: SPF: Fail / DKIM: Fail / DMARC: Fail
Confirmed Click: Observed - vikas.jain@company.com
Reply-To Mismatch: support@verify-paypal-center.ru
Assessment: Confirmed Phishing Campaign - Credential Harvesting

Priority: High
A coordinated phishing campaign targeting multiple employees was 
detected, with at least one confirmed click on a credential-harvesting 
link.

================================================================

03. EMAIL GATEWAY LOG FIELDS

spf - Sender Policy Framework result - Detect sender domain spoofing
dkim - DomainKeys Identified Mail result - Detect message tampering/spoofing
dmarc - Domain-based Message Authentication result - Combined authentication policy verdict
reply_to - Reply-To address - Detect mismatch from sender (spoofing indicator)
src_ip - Sending server IP - Identify and block malicious infrastructure
url - Embedded link - Identify phishing/credential-harvesting pages
attachment_name - Attached file name - Detect malicious payloads (e.g. double extensions)
attachment_hash - File hash of attachment - Cross-reference against threat intelligence
action - Delivered vs. Clicked - Determine real user impact and severity

================================================================

04. DETECTION LOGIC

The detection identifies emails failing SPF, DKIM, or DMARC 
authentication, which is the primary indicator of a spoofed or 
unauthorized sender.

Detection Threshold
Any single field (spf, dkim, or dmarc) returning a "fail" result is 
flagged for review.

SPL Detection Query:
index=gmail spf="fail" OR dkim="fail" OR dmarc="fail"
| table time, sender, recipient, subject, spf, dkim, dmarc, src_ip

Detection Result
- Suspicious emails flagged: 6
- Distinct malicious sender domains: 4
- Primary campaign sender: accounts@paypa1-secure-billing.com
- Recipients targeted by primary campaign: 3

================================================================

05. EVIDENCE - AUTHENTICATION FAILURE DETECTION

The Splunk search identified multiple emails failing SPF, DKIM, and 
DMARC checks, separating suspicious traffic from legitimate internal 
and vendor email.

[Screenshot: screenshots/03-auth-failures.png]
Figure 1 - Emails failing SPF/DKIM/DMARC identified by Splunk.

================================================================

06. CAMPAIGN CORRELATION

After identifying the failed-authentication emails, the primary sender 
(accounts@paypa1-secure-billing.com) was isolated to determine the 
scope of the campaign.

Result - A coordinated campaign was identified:
- Sender: accounts@paypa1-secure-billing.com
- Source IP: 91.108.56.23
- Recipients: ananya.rao, vikas.jain, rohit.mehta
- Time Window: 09:14:03 - 09:15:02 (59 seconds)
- Confirmed Click: vikas.jain@company.com

[Screenshot: screenshots/04-campaign-detected.png]
Figure 2 - Same sender targeting multiple recipients within a 59-second window.

Analyst Observation: The identical subject line, rapid send timing, and 
consistent sender across three recipients confirms this was an 
automated phishing campaign rather than a single isolated email.

================================================================

07. MALICIOUS ATTACHMENT INVESTIGATION

The investigation then checked for attachments across all indexed 
emails to identify potential malware delivery.

Result - One malicious attachment was identified, disguised using a 
double file extension technique.

- Sender: invoices@globalfreight-logistics.com
- Source IP: 198.51.100.44
- Attachment: Invoice_INV99214.pdf.exe
- Attachment Hash: c3f9a1e2b7d84f6a9e0c1b2d3f4a5e6b
- SPF/DKIM/DMARC: Pass (all three)
- Action: Clicked - ananya.rao@company.com

[Screenshot: screenshots/05-malicious-attachment.png]
Figure 3 - Malicious executable disguised as a PDF invoice.

Analyst Observation: This email passed all authentication checks, 
demonstrating that SPF/DKIM/DMARC alone are not sufficient for 
detection - the sending domain was likely newly registered or 
compromised, and required manual triage.

================================================================

08. REPLY-TO MISMATCH ANALYSIS

Sender and Reply-To fields were compared across all indexed emails to 
identify additional spoofing indicators.

Findings:
- accounts@paypa1-secure-billing.com -> support@verify-paypal-center.ru (Mismatch: Yes)
- security-alert@0ffice365-verify.com -> admin@account-verify-center.xyz (Mismatch: Yes)

[Screenshot: screenshots/06-replyto-mismatch.png]
Figure 4 - Reply-To
