import click
from spectre_engine.modules.waf_detector import detect_waf

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

    # --- Placeholder for actual port scanning logic ---
    results = {
        "target": target,
        "open_ports": [
            {"port": 80, "service": "http", "version": "nginx/1.18.0"},
            {"port": 443, "service": "https", "version": "nginx/1.18.0"}
        ]
    }

    if json:
        import json as json_lib
        click.echo(json_lib.dumps(results, indent=4))
    else:
        click.secho("\n[+] Open Ports Found:", fg='green', bold=True)
        for port_info in results["open_ports"]:
            click.echo(f"    - Port {port_info['port']}: {port_info['service']} ({port_info['version']})")

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
    detected_waf = detect_waf(target)
    
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

if __name__ == '__main__':
    spectre()