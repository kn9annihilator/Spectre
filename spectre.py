import click
from spectre_engine.modules.waf_detector import detect_waf
from spectre_engine.modules.firewall_profiler import run_scan
from spectre_engine.modules.infra_detector import detect_infrastructure # Add this line

# This is the main command group, e.g., 'spectre'
@click.group()
def spectre():
    """
    Spectre: An advanced security architecture fingerprinting tool.
    """
    pass

# This creates a subcommand group, e.g., 'scan'
@click.group()
def scan():
    """
    Commands to perform scans on a target.
    """
    pass

# --- THE FIX IS HERE ---
# This line is crucial. It tells the main 'spectre' command
# that the 'scan' group is one of its subcommands.
spectre.add_command(scan)
# --- END OF FIX ---

# This is our new command for firewall/port scanning
# This is our new command for firewall/port scanning
@scan.command()
@click.argument('target')
@click.option('--ports', default='1-1024', help='The port range to scan (e.g., 22,80,443 or 1-1024).')
@click.option('--profile', default='normal', type=click.Choice(['stealth', 'normal', 'aggressive']), help='Scan profile to use.')
@click.option('--json', is_flag=True, help='Output results in JSON format.')
def firewall(target, ports, profile, json):
    """
    Profile the target's firewall and scan for open ports.
    """
    click.echo(f"[*] Profiling firewall for target: {target}")
    click.echo(f"    - Port Range: {ports}")
    click.echo(f"    - Scan Profile: {profile}")

    # Map profile to the number of threads for speed
    thread_map = {'stealth': 10, 'normal': 50, 'aggressive': 100}
    num_threads = thread_map[profile]

    # --- Call the firewall profiler module ---
    open_ports_list = run_scan(target, ports, num_threads)

    results = {
        "target": target,
        "open_ports": open_ports_list
    }

    if json:
        import json as json_lib
        click.echo(json_lib.dumps(results, indent=4))
    else:
        click.secho("\n[+] Open Ports Found:", fg='green', bold=True)
        if not open_ports_list:
            click.echo("    - None")
        else:
            for port_info in open_ports_list:
                click.echo(f"    - Port {port_info['port']}: {port_info['banner'] if port_info['banner'] else 'No banner received'}")
# This is a specific command, e.g., 'spectre scan waf'
@scan.command()
@click.argument('target')
@click.option('--profile', default='normal', type=click.Choice(['stealth', 'normal', 'aggressive']), help='Scan profile to use.')
@click.option('--json', is_flag=True, help='Output results in JSON format.')
def waf(target, profile, json):
    """
    Probe for Web Application Firewall (WAF) and CDN presence.
    """
    click.echo(f"[*] Probing WAF/CDN for target: {target}")
    click.echo(f"    - Scan Profile: {profile}")
    
    # --- Call the WAF detector module ---
    detected_waf = waf(target)
    
    results = {
        "target": target,
        "waf_detected": detected_waf if detected_waf else "None",
        "detection_method": "Signature Matching"
    }
    
    if json:
        import json as json_lib
        click.echo(json_lib.dumps(results, indent=4))
    else:
        click.secho("\n[+] Results:", fg='green', bold=True)
        click.echo(f"    - WAF/CDN Detected: {results['waf_detected']}")
        click.echo(f"    - Detection Method: {results['detection_method']}")

# This is our new command for infrastructure detection
@scan.command()
@click.argument('target')
@click.option('--json', is_flag=True, help='Output results in JSON format.')
def infra(target, json):
    """
    Detect infrastructure like reverse proxies and load balancers.
    """
    click.echo(f"[*] Detecting infrastructure for target: {target}")

    # --- Call the infrastructure detector module ---
    infra_results = detect_infrastructure(target)

    if json:
        import json as json_lib
        click.echo(json_lib.dumps(infra_results, indent=4))
    else:
        # Print Header Findings
        click.secho("\n[+] Header Analysis:", fg='green', bold=True)
        if not infra_results["headers"]:
            click.echo("    - No revealing headers found.")
        else:
            for item in infra_results["headers"]:
                click.echo(f"    - Found Header: {click.style(item['header'], bold=True)}: {item['value']}")
                click.echo(f"      > {item['description']}")

        # Print DNS Findings
        click.secho("\n[+] DNS-Based Load Balancing:", fg='green', bold=True)
        dns_info = infra_results["dns_load_balancing"]
        if dns_info["detected"]:
            click.secho(f"    - Detected: Yes", fg='yellow')
            click.echo(f"      > Domain resolves to multiple IP addresses: {', '.join(dns_info['ips'])}")
        else:
            click.echo(f"    - Detected: No")
            click.echo(f"      > Domain consistently resolves to: {', '.join(dns_info['ips'])}")

if __name__ == '__main__':
    spectre()