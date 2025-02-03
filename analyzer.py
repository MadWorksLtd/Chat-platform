import socket
import nmap  # You'll need to install this: pip install python-nmap
import vulners  # You'll need to install this: pip install vulners

def scan_and_analyze(ip_address, output_file="port_scan_report.txt"):
    """
    Scans an IP address for open ports, analyzes vulnerabilities,
    suggests attacks, and saves the report to a text file.
    """

    try:
        nm = nmap.PortScanner()
        nm.scan(ip_address, '1-1024')  # Scan ports 1 to 1024 (you can adjust this range)

        report = f"Port Scan Report for {ip_address}\n\n"

        for host in nm.all_hosts():
            report += f"Host: {host}\n"
            if nm[host].state() == 'up':
                for protocol in nm[host].all_protocols():
                    lport = nm[host][protocol].keys()
                    for port in lport:
                        state = nm[host][protocol][port]['state']
                        if state == 'open':
                            report += f"  Port: {port}/{protocol} - State: {state}\n"

                            # Vulnerability Analysis (using vulners)
                            try:
                                v = vulners.Vulners()
                                # Search for vulnerabilities related to the service running on the open port
                                # (This requires some guesswork about the service)
                                service_name = nm[host][protocol][port]['name']  # Get service name
                                if service_name:                                 
                                    vulns = v.search(f"{service_name} {protocol} {port}")
                                    if vulns:
                                        report += "    Vulnerabilities:\n"
                                        for vuln in vulns:
                                            report += f"      - {vuln['title']} ({vuln['href']})\n"
                                            # Suggest potential attacks (basic examples)
                                            report += "      Potential Attacks:\n"
                                            if "http" in service_name:
                                                report += "        - Cross-site scripting (XSS)\n"
                                                report += "        - SQL injection\n"
                                            elif "ssh" in service_name:
                                                report += "        - Brute-force attack\n"
                                                report += "        - Man-in-the-middle attack\n"
                                            elif "ftp" in service_name:
                                                report += "        - Anonymous login\n"
                                                report += "        - Buffer overflow\n"
                                            report += "\n"
                                    else:
                                        report += "    No known vulnerabilities found.\n\n"
                                else:
                                    report += "    Could not determine service name for vulnerability scan.\n\n"


                            except Exception as e:
                                report += f"    Vulnerability scan failed: {e}\n\n"

            else:
                report += "  Host is down or filtered.\n\n"

        # Save the report to a file
        with open(output_file, "w") as f:
            f.write(report)

        print(f"Scan report saved to {output_file}")

    except socket.gaierror:
        print("Invalid IP address.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    ip_address = input("Enter the IP address to scan: ")
    scan_and_analyze(ip_address)

    