import gradio as gr
from verifier import load_whitelist, load_suspicious_tlds, analyze_url

# Load rules
whitelist_map, official_domains_set = load_whitelist("whitelist.yml")
suspicious_tlds_set = load_suspicious_tlds("data/suspicious_tlds.txt")

def check_url(url):
    if not url.strip():
        return {"Error": "Please enter a URL"}
    
    result = analyze_url(url, whitelist_map, official_domains_set, suspicious_tlds_set)
    return {
        "Input URL": result["input_url"],
        "Normalized URL": result["normalized_url"],
        "Risk Score": result["risk_score"],
        "Verdict": result["verdict"],
        "Reasons": "; ".join(result["reasons"]) if result["reasons"] else "None"
    }

# Gradio UI
iface = gr.Interface(
    fn=check_url,
    inputs=gr.Textbox(label="Enter Download Link"),
    outputs=gr.JSON(label="Analysis Result"),
    title="Malicious URL detector",
    description="Check if a software download link is safe or suspicious using simple cybersecurity heuristics."
)

if __name__ == "__main__":
    iface.launch(share=True)   # share=True gives a public link
