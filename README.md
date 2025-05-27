# phishing-email-analysis-task

Task Overview

This report is part of a cybersecurity internship task focused on identifying and analyzing phishing emails. The task involved reviewing a suspicious email, examining its contents and headers, and identifying phishing indicators.


Email Summary

Subject: Your Amazon Account is Locked – Immediate Action Required
  Sender: `alert@amaz0n-support.com` (spoofed address)
  Link:`https://amazon.verify-account-secure.com` (malicious)
  Attachment: `Amazon_Verification_Form.docm` (macro-enabled document)


Analysis Performed

Email Body Indicators

| Indicator             | Description                                                            |

| Spoofed Email Address | Looks like a legit Amazon email but uses `amaz0n` instead of `amazon`. |
| Suspicious URL        | URL mimics Amazon but redirects to an unknown domain.                  |
| Urgent Language       | Creates panic: "Immediate Action Required", 24-hour deadline.          |
| Malicious Attachment  | `.docm` file that can contain malware macros.                          |
| Generic Greeting      | Uses "Dear Customer" instead of a real name.                           |
| Grammar & Tone        | Slightly off, designed to trigger fear.                                |

Header Analysis

| Check     | Result          | Explanation                                              |

| SPF       | ❌ Fail          | Sending IP not authorized to send emails for the domain. |
| DKIM      | ❌ Fail          | Signature validation failed.                             |
| DMARC     | ❌ Fail          | Policy not followed.                                     |
| Origin IP | `185.244.25.92` | Not associated with Amazon, possibly a known spam IP.    |



Tools Used

MxToolbox Email Header Analyzer
Email client (for viewing full headers)
Browser (for URL inspection via hover)


Conclusion
This email is a classic phishing attempt designed to steal user credentials or spread malware. The report documents:

 Technical evidence (header failures)
 Social engineering tactics
 Malicious indicators (URL, file type, spoofed domain)

Do not click any links or download attachments from suspicious emails. Report them immediately.

Files included 
Phishing_email_task_ss.pdf – Contains screenshots of the phishing email and analysis highlights.
Report_sanika.pdf – Detailed phishing email analysis report authored by Sanika.
email_actual.txt – Raw text version of the phishing email's body content.
email_header.txt – Extracted email header used for technical analysis of spoofing and authentication.
README.md – Overview of the task, tools used, analysis summary, and conclusions.


