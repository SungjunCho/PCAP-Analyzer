# PCAP-Analyzer
PCAP Analyzer – AI-Assisted Detection Engineering Tool


Overview

This project presents an experimental Detection Engineering Automation Framework designed to support IPS/IDS rule drafting workflows.

The system analyzes uploaded PCAP files, extracts full payload data, detects suspicious patterns, and automatically generates draft Snort rules. Additionally, it provides payload visualization (Hex + ASCII), rule specificity scoring, and false positive estimation.

This tool does not replace detection engineers, but assists in accelerating the initial rule drafting process.


A web app that analyzes PCAP files and generates Snort rules with false positive scoring.

## 🚀 Quick Start

```bash
# Clone and install
git clone https://github.com/yourusername/pcap-analyzer.git
cd pcap-analyzer
pip install -r requirements.txt

# Run multi-file version (recommended)
python app_multi.py

# OR run single-file version
python app_single.py
Then open http://127.0.0.1:5000

📦 Two Versions Available
Feature	app_single.py (v1.0)	app_multi.py (v2.0) ⭐
File Upload	Single file only	Multiple files
Drag & Drop	❌	✅
Progress Bar	❌	✅
Export Rules	❌	✅ (single file or ZIP)
Max File Size	100MB	500MB
Status	⚠️ Deprecated	✅ Recommended
📁 Project Structure
text
pcap-analyzer/
├── app_multi.py          # ✅ New multi-file version
├── app_single.py         # ⚠️ Legacy single-file version
├── requirements.txt      # Dependencies
├── templates/
│   ├── multi_upload.html # UI for v2.0
│   └── index.html        # UI for v1.0
└── static/
    └── style.css         # Shared styles
🎯 Which Version Should I Use?
Use app_multi.py (v2.0) if you need:
Multiple file analysis

Batch processing

Export features

Better performance

Use app_single.py (v1.0) if you:
Need quick single file check

Have limited resources

Want minimal interface

🔧 Quick Example
Multi-file version:

bash
python app_multi.py
# Drag & drop multiple .pcap files
# Click "Analyze"
# Download results as ZIP
Single-file version:

bash
python app_single.py
# Select one .pcap file
# View basic results
📝 Requirements
text
Flask==2.3.0
scapy==2.5.0
🤝 Contributing
Fork it

Create feature branch

Commit changes

Push to branch

Open Pull Request
