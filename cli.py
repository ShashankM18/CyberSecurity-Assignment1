import argparse, json, sys, os
from verifier import load_whitelist, load_suspicious_tlds, analyze_url

def main():
    parser = argparse.ArgumentParser(description="Verify software download links.")
    parser.add_argument("--url", help="Single URL to check.")
    parser.add_argument("--file", help="File with URLs (one per line).")
    parser.add_argument("--whitelist", default="whitelist.yml", help="Path to whitelist YAML.")
    parser.add_argument("--tlds", default="data/suspicious_tlds.txt", help="Path to suspicious TLD list.")
    args = parser.parse_args()

    if not args.url and not args.file:
        print("Provide --url or --file", file=sys.stderr)
        sys.exit(2)

    whitelist_map, official_domains_set = load_whitelist(args.whitelist)
    suspicious_tlds_set = load_suspicious_tlds(args.tlds)

    def check_one(u):
        result = analyze_url(u, whitelist_map, official_domains_set, suspicious_tlds_set)
        print(json.dumps(result, indent=2))

    if args.url:
        check_one(args.url)
    if args.file:
        if not os.path.exists(args.file):
            print(f"File not found: {args.file}", file=sys.stderr)
            sys.exit(2)
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                check_one(line)

if __name__ == "__main__":
    main()
