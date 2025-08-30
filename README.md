# Malicious URL Detector
The Malicious URL Detector tool is a lightweight cybersecurity project that helps users determine whether a software download link is safe, official, or suspicious.

It uses simple heuristics and rule-based checks instead of heavy machine learning models. The system verifies links based on:

✅ Official domain whitelist matching

✅ HTTPS protocol check

✅ Suspicious TLD detection (e.g., .zip, .xyz, .top)

✅ Typosquatting similarity detection (e.g., pyth0n.org)

✅ Shady path keywords (crack, serial, license-key)

The project includes both a command-line interface (CLI) and a user-friendly Gradio web interface with a shareable public link for demos.

This tool is designed to be open-source, beginner-friendly, and educational, making it a simple introduction to how cybersecurity checks can protect users from malicious downloads.
