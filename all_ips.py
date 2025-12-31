import ipaddress
import subprocess
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_all_prefixes_from_asn(asn):
    print(f"Getting prefixes for {asn}...")
    
    try:
        cmd = ["whois", "-h", "whois.radb.net", "--", "-i", "origin", asn]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print(f"Error: {result.stderr}")
            return []
        
        prefixes = []
        for line in result.stdout.split('\n'):
            if line.strip().startswith('route:'):
                prefix = line.split('route:')[1].strip()
                if '/' in prefix:
                    prefixes.append(prefix)
        
        print(f"Found {len(prefixes)} prefixes for {asn}")
        return sorted(set(prefixes))
        
    except Exception as e:
        print(f"Error: {e}")
        return []

def generate_ips_for_prefix(prefix):
    try:
        network = ipaddress.ip_network(prefix, strict=False)
        ips = [str(ip) for ip in network]
        return prefix, ips, len(ips)
    except Exception as e:
        print(f"Error at prefix {prefix}: {e}")
        return prefix, [], 0

def save_all_ips(prefixes, output_file):
    print(f"\nCollecting all IP addresses")
    print("=" * 60)
    
    total_ips = 0
    prefix_stats = []
    
    with open(output_file, 'w') as f:
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_prefix = {executor.submit(generate_ips_for_prefix, prefix): prefix for prefix in prefixes}
            
            for future in as_completed(future_to_prefix):
                prefix = future_to_prefix[future]
                try:
                    prefix, ips, count = future.result()
                    
                    for ip in ips:
                        f.write(f"{ip}\n")
                    
                    total_ips += count
                    prefix_stats.append((prefix, count))
                    
                    print(f"Collected {prefix}: {count:,} IP addresses")
                    
                except Exception as e:
                    print(f"Error collecting {prefix}: {e}")
    
    return output_file, total_ips, prefix_stats

def main():
    parser = argparse.ArgumentParser(description='Collect all IP addresses for an ASN')
    parser.add_argument('--asn', type=str, 
                       help='ASN number (ex: AS8945, AS12345)')
    parser.add_argument('--output', type=str, default='ALL_IPS_ASN.txt',
                       help='Output file name')
    parser.add_argument('--batch', action='store_true',
                       help='Never ask for user input, use the default behavior')
    
    args = parser.parse_args()
    
    asn = args.asn.upper()
    if not asn.startswith('AS'):
        asn = 'AS' + asn
    
    print(f"ASN: {asn}")
    print(f"Output: {args.output}")
    
    prefixes = get_all_prefixes_from_asn(asn)
    
    if not prefixes:
        print("No prefixes found")
        sys.exit(1)
    
    print(f"\nTotal prefixes found: {len(prefixes)}")
    
    if not args.batch:
        print("\n" + "=" * 60)
        print(f"WARNING: You will collect A LOT of IP addresses!")
        response = input("Do you want to continue? (yes/no): ")
        
        if response.lower() not in ['ye','yes', 'y']:
            print("Operation cancelled.")
            sys.exit(0)
    
    print(f"\nCollecting IP addresses in {args.output}...")
    
    output_file, total_ips, prefix_stats = save_all_ips(prefixes, args.output)
    
    print(f"\nCollection complete!")
    print("=" * 60)
    print(f"File: {output_file}")
    print(f"Total IP addresses collected: {total_ips:,}")
    print(f"Total prefixes processed: {len(prefix_stats)}")
    

if __name__ == "__main__":
    main()