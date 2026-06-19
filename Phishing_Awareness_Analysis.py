import re

def analyze_message(message):

    red_flags = []
    explanations_found = []
    risk_score = 0

    message_lower = message.lower()

    explanations = {
        "offer": "Unexpected offers may be used to lure users into scams.",
        "discount": "Fake discounts are often used to attract victims.",
        "promotion": "Promotional messages can hide phishing links.",
        "reward": "Attackers use rewards to manipulate users.",
        "free": "Free gifts are a common phishing bait.",
        "winner": "Claiming you are a winner is a common scam tactic.",
        "congratulations": "Unexpected prizes may indicate phishing.",
        "gift": "Fake gift offers often lead to malicious websites.",
        "bonus": "Unusual bonuses may be used to deceive users.",
        "limited time": "Time pressure is often used in scams.",

        "urgent": "Creates pressure and reduces careful thinking.",
        "verify": "Attackers often request account verification.",
        "login": "May redirect users to fake login pages.",
        "update account": "Can trick users into revealing credentials.",
        "security alert": "Fake alerts create panic and urgency.",
        "account suspended": "Used to scare users into acting quickly.",
        "confirm": "May be an attempt to steal personal information.",
        "validate": "Attackers use validation requests to collect data.",
        "immediately": "Urgency is a common social engineering tactic.",
        "click here": "Links may lead to fake or malicious websites.",

        "password": "Requests for passwords indicate credential theft.",
        "otp": "OTPs should never be shared with anyone.",
        "bank details": "Sensitive banking information may be targeted.",
        "credit card": "Credit card information can be stolen.",
        "debit card": "Debit card details are valuable to attackers.",
        "cvv": "CVV information should never be shared.",
        "wire transfer": "Fraudsters use fake transfer requests.",
        "pin": "PIN numbers are confidential information.",
        "payment information": "May indicate financial fraud attempts.",
        "bank account": "Attackers often target banking credentials."
    }

    low_risk_keywords = [
        "offer", "discount", "promotion", "reward",
        "free", "winner", "congratulations",
        "gift", "bonus", "limited time"
    ]

    medium_risk_keywords = [
        "urgent", "verify", "login",
        "update account", "security alert",
        "account suspended", "confirm",
        "validate", "immediately",
        "click here"
    ]

    high_risk_keywords = [
        "password", "otp", "bank details",
        "credit card", "debit card",
        "cvv", "wire transfer",
        "pin", "payment information",
        "bank account"
    ]

    suspicious_domains = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "rb.gy",
        "t.co"
    ]

    # Low Risk Detection
    for keyword in low_risk_keywords:
        if keyword in message_lower:
            red_flags.append(f"Low Risk Keyword: {keyword}")
            explanations_found.append(explanations[keyword])
            risk_score += 5

    # Medium Risk Detection
    for keyword in medium_risk_keywords:
        if keyword in message_lower:
            red_flags.append(f"Medium Risk Keyword: {keyword}")
            explanations_found.append(explanations[keyword])
            risk_score += 10

    # High Risk Detection
    for keyword in high_risk_keywords:
        if keyword in message_lower:
            red_flags.append(f"High Risk Keyword: {keyword}")
            explanations_found.append(explanations[keyword])
            risk_score += 20

    # Suspicious Shortened URLs
    for domain in suspicious_domains:
        if domain in message_lower:
            red_flags.append(f"Suspicious Domain: {domain}")
            explanations_found.append(
                "URL shorteners can hide the real destination website."
            )
            risk_score += 20

    # Regex URL Detection
    urls = re.findall(
        r'https?://\S+|www\.\S+',
        message
    )

    if urls:
        red_flags.append("Suspicious URL Detected")
        explanations_found.append(
            "Links should be verified before clicking."
        )
        risk_score += 15

    # Social Engineering - Urgency
    if (
        "urgent" in message_lower or
        "immediately" in message_lower
    ):
        red_flags.append(
            "Social Engineering: Urgency Tactic"
        )
        explanations_found.append(
            "Urgency pressures users into making quick decisions."
        )
        risk_score += 15

    # Suspicious Attachments
    suspicious_files = [
        ".exe",
        ".zip",
        ".scr",
        ".bat"
    ]

    for file_type in suspicious_files:
        if file_type in message_lower:
            red_flags.append(
                f"Suspicious Attachment: {file_type}"
            )
            explanations_found.append(
                "Executable attachments may contain malware."
            )
            risk_score += 20

    # Excessive Exclamation Marks
    if message.count("!") > 2:
        red_flags.append(
            "Social Engineering: Excessive Exclamation Marks"
        )
        explanations_found.append(
            "Excessive punctuation is often used to create panic."
        )
        risk_score += 10

    # Excessive Capital Letters
    capital_count = sum(
        1 for char in message
        if char.isupper()
    )

    if capital_count > 20:
        red_flags.append(
            "Social Engineering: Excessive Capital Letters"
        )
        explanations_found.append(
            "Capital letters are often used to create urgency."
        )
        risk_score += 10

    risk_score = min(risk_score, 100)

    return red_flags, explanations_found, risk_score


# Main Program
print("=" * 60)
print("THREAT ANALYZER")
print("=" * 60)

message = input(
    "\nEnter the message to analyze:\n"
)

results, reasons, risk_score = analyze_message(message)

# Verdict
if risk_score >= 60:
    verdict = "HIGH RISK"
elif risk_score >= 30:
    verdict = "MEDIUM RISK"
else:
    verdict = "LOW RISK"

print("\n THREAT ANALYSIS REPORT")
print("-" * 60)

if results:

    print("\n⚠ THREATS DETECTED:\n")

    for i in range(len(results)):
        print(f"{i + 1}. {results[i]}")
        print(f"   Reason: {reasons[i]}\n")

else:
    print("\n✅ No Threats Detected")

# Summary
print("\nSUMMARY")
print("-" * 60)
print("Total Threats Found:", len(results))
print("Risk Score:", risk_score, "/100")
print("Threat Level:", verdict)

# Recommendations
print("\nSECURITY RECOMMENDATIONS")
print("-" * 60)

if verdict == "HIGH RISK":
    print("• Do NOT click any links.")
    print("• Do NOT share passwords or OTPs.")
    print("• Verify sender identity.")
    print("• Report the message as phishing.")

elif verdict == "MEDIUM RISK":
    print("• Be cautious before responding.")
    print("• Verify sender authenticity.")
    print("• Avoid sharing sensitive information.")

else:
    print("• No major phishing indicators found.")
    print("• Continue following safe online practices.")

# Save Report
try:
    with open(
        "phishing_report.txt",
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "THREAT ANALYSIS REPORT\n"
        )
        file.write("-" * 60 + "\n")

        if results:
            file.write(
                "\nTHREATS DETECTED:\n\n"
            )

            for i in range(len(results)):
                file.write(
                    f"{i + 1}. {results[i]}\n"
                )
                file.write(
                    f"   Reason: {reasons[i]}\n\n"
                )

        else:
            file.write(
                "\nNo Threats Detected\n"
            )

        file.write("\nSUMMARY\n")
        file.write("-" * 60 + "\n")
        file.write(
            f"Total Threats Found: {len(results)}\n"
        )
        file.write(
            f"Risk Score: {risk_score}/100\n"
        )
        file.write(
            f"Threat Level: {verdict}\n"
        )

    print(
        "\nReport saved successfully as "
        "'phishing_report.txt'"
    )

except Exception as e:
    print(
        "\nError saving report:",
        e
    )