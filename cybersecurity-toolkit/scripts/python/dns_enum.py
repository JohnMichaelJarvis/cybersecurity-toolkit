#!/usr/bin/env python3

import dns.resolver

domain = "example.com"
records = ["A", "AAAA", "MX", "NS", "TXT"]

for record in records:
    try:
        answers = dns.resolver.resolve(domain, record)
        print(f"\n{record} Records for {domain}:")
        for rdata in answers:
            print(rdata.to_text())
    except Exception as e:
        print(f"{record} record query failed: {e}")
