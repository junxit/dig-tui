# 100 Useful `dig` Commands

This guide provides 100 practical examples of using `dig` (Domain Information Groper) for DNS troubleshooting, reconnaissance, and administration.

## 1. Basic Queries
1. `dig example.com` - Standard A record lookup (default behavior).
2. `dig example.com A` - Explicitly request the A (IPv4) record.
3. `dig example.com AAAA` - Request the AAAA (IPv6) record.
4. `dig example.com ANY` - Request all available records (note: often blocked or restricted by modern DNS servers to prevent amplification attacks).
5. `dig -t A example.com` - Alternative syntax to specify the record type (A).
6. `dig -t AAAA example.com` - Alternative syntax to specify the record type (AAAA).
7. `dig example.com. +defname` - Append the default search list to the query.
8. `dig example.com. +search` - Use the search domains defined in `/etc/resolv.conf`.
9. `dig +short example.com` - Return only the IP address (short output).
10. `dig +short example.com AAAA` - Return only the IPv6 address.

## 2. Querying Specific Record Types
11. `dig example.com MX` - Look up Mail Exchange (MX) records.
12. `dig example.com NS` - Look up Name Server (NS) records.
13. `dig example.com TXT` - Look up Text (TXT) records (useful for SPF, DKIM).
14. `dig example.com SOA` - Look up Start of Authority (SOA) record.
15. `dig example.com CNAME` - Look up Canonical Name (CNAME) record.
16. `dig example.com SRV` - Look up Service (SRV) records.
17. `dig example.com PTR` - Look up Pointer (PTR) records directly (though `-x` is more common).
18. `dig example.com CAA` - Look up Certification Authority Authorization (CAA) records.
19. `dig example.com HINFO` - Look up Host Information (HINFO) records.
20. `dig example.com NAPTR` - Look up Name Authority Pointer (NAPTR) records.

## 3. More Advanced Record Types & Subdomains
21. `dig www.example.com CNAME` - Check CNAME for the `www` subdomain.
22. `dig _dmarc.example.com TXT` - Look up the DMARC policy for a domain.
23. `dig _domainkey.example.com TXT` - Check for base DKIM records.
24. `dig _sip._tcp.example.com SRV` - Look up a SIP service running over TCP.
25. `dig example.com ALIAS` - Attempt to query an ALIAS (pseudo-record used by some providers).
26. `dig example.com LOC` - Look up Location (LOC) records (rarely used).
27. `dig example.com CERT` - Look up Certificate (CERT) records.
28. `dig example.com SSHFP` - Look up SSH Public Key Fingerprint (SSHFP) records.
29. `dig example.com TLSA` - Look up TLSA certificate association records.
30. `dig example.com URI` - Look up URI mapping records.

## 4. Reverse DNS Lookups
31. `dig -x 8.8.8.8` - Reverse lookup for Google's public IPv4 address.
32. `dig -x 1.1.1.1` - Reverse lookup for Cloudflare's public IPv4 address.
33. `dig -x 2001:4860:4860::8888` - Reverse lookup for an IPv6 address.
34. `dig -x 8.8.8.8 +short` - Get only the hostname from a reverse lookup.
35. `dig -x 192.168.1.1` - Reverse lookup for a local private IP address.
36. `dig PTR 8.8.8.8.in-addr.arpa` - Manual IPv4 reverse lookup without the `-x` flag.
37. `dig PTR 1.0.0.127.in-addr.arpa` - Manual reverse lookup for the localhost address.
38. `dig PTR b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa` - Manual IPv6 reverse lookup.
39. `dig -x 8.8.8.8 +noall +answer` - Clean and concise output for a reverse lookup.
40. `dig -x 1.1.1.1 +multiline` - Highly readable formatted reverse lookup.

## 5. Querying Specific Nameservers
41. `dig @8.8.8.8 example.com` - Query Google's public DNS servers.
42. `dig @1.1.1.1 example.com` - Query Cloudflare's public DNS servers.
43. `dig @9.9.9.9 example.com` - Query Quad9's public DNS servers.
44. `dig @208.67.222.222 example.com` - Query OpenDNS servers.
45. `dig @a.root-servers.net example.com` - Query a root name server directly.
46. `dig @ns1.google.com google.com` - Query a domain's authoritative nameserver directly.
47. `dig @8.8.8.8 example.com MX` - Query Google DNS specifically for MX records.
48. `dig @1.1.1.1 example.com TXT +short` - Query Cloudflare for TXT records and get a clean output.
49. `dig @127.0.0.53 example.com` - Query the local systemd-resolved stub resolver (Linux).
50. `dig @10.0.0.1 example.com` - Query a specific internal network DNS server.

## 6. Output Formatting
51. `dig example.com +multiline` - Display SOA and other records in a human-readable, multi-line format.
52. `dig example.com +nocomments` - Hide the initial comment block in the output.
53. `dig example.com +nostats` - Hide the query statistics at the end of the output.
54. `dig example.com +noquestion` - Hide the question section in the output.
55. `dig example.com +noauthority` - Hide the authority section.
56. `dig example.com +noadditional` - Hide the additional section.
57. `dig example.com +nocmd` - Hide the initial command header.
58. `dig example.com +noall` - Turn off all display sections (usually followed by enabling one).
59. `dig example.com +noall +answer` - Display ONLY the answer section (very common for clean output).
60. `dig example.com +onesoa` - Print only one SOA record when performing an AXFR.

## 7. Clean and Concise Output
61. `dig +short example.com` - Extremely minimal output (returns just the IP or value).
62. `dig +short example.com MX` - Minimal output for MX (shows priority and hostname only).
63. `dig +short example.com TXT` - Minimal output for TXT records (shows just the quoted string).
64. `dig +short -x 8.8.8.8` - Minimal output for reverse IP mapping (just the hostname).
65. `dig example.com +noall +answer +stats` - Show only the answer block and the query time/stats.
66. `dig example.com +short +identify` - Short output but includes the IP of the server that provided the answer.
67. `dig example.com +qr` - Print the exact query that was sent before displaying the answer.
68. `dig example.com +yaml` - Output the response in YAML format (available in newer versions of BIND/dig).
69. `dig example.com +json` - Output the response in JSON format (available in newer versions of BIND/dig).
70. `dig example.com +rrcomments` - Show per-record comments if they are available.

## 8. Tracing, Debugging, and Performance
71. `dig example.com +trace` - Trace the delegation path from the root nameservers down to the domain.
72. `dig example.com +trace +nodnssec` - Perform a trace but disable DNSSEC validation during the process.
73. `dig example.com +nssearch` - Find all authoritative nameservers for a domain and display their SOA records.
74. `dig example.com +time=2` - Set the query timeout to 2 seconds.
75. `dig example.com +tries=1` - Only try the query once (do not automatically retry).
76. `dig example.com +retry=0` - Set the number of UDP retries to 0.
77. `dig example.com +ndots=2` - Set the number of dots for absolute names (overrides resolv.conf).
78. `dig example.com +fail` - Stop querying upon encountering a SERVFAIL (default behavior).
79. `dig example.com +nofail` - Continue to the next server if a SERVFAIL is received.
80. `dig example.com +besteffort` - Print whatever data is received, even if the packet is malformed.

## 9. Network and Connection Options
81. `dig example.com +tcp` - Force the query to use TCP instead of UDP.
82. `dig example.com +vc` - Same as `+tcp` (Virtual Circuit).
83. `dig example.com +notcp` - Force the query to use UDP (this is the default).
84. `dig example.com -4` - Force the use of IPv4 for the query transport.
85. `dig example.com -6` - Force the use of IPv6 for the query transport.
86. `dig example.com -p 5353` - Query on a specific, non-standard port (e.g., 5353 for mDNS).
87. `dig @127.0.0.1 -p 8600 example.com` - Query a local Consul DNS server running on port 8600.
88. `dig example.com -b 192.168.1.100` - Bind to a specific local source IP address before querying.
89. `dig example.com +keepopen` - Keep the TCP socket open between queries (often used with `-f`).
90. `dig example.com +ignore` - Ignore truncation in UDP responses (do not automatically retry with TCP).

## 10. DNSSEC, Security, and Advanced
91. `dig example.com +dnssec` - Request DNSSEC records (RRSIG, NSEC, etc.) along with the answer.
92. `dig example.com +do` - Set the "DNSSEC OK" (DO) bit in the query to signal DNSSEC support.
93. `dig example.com +cdflag` - Set the "Checking Disabled" (CD) bit to bypass validation.
94. `dig example.com DNSKEY` - Look up the DNS Public Key for a domain.
95. `dig example.com DS` - Look up the Delegation Signer (DS) record.
96. `dig @ns1.example.com example.com AXFR` - Attempt a full zone transfer (often restricted by security policies).
97. `dig @ns1.example.com example.com IXFR=2023010100` - Attempt an incremental zone transfer from a specific SOA serial number.
98. `dig -f domains.txt` - Read queries from a file (`domains.txt`) and execute them in bulk.
99. `dig -f domains.txt +short` - Bulk query from a file and output only the short results for brevity.
100. `dig @bind-server version.bind CHAOS TXT` - Query the version of a BIND DNS server (often blocked, but good to know for auditing).
