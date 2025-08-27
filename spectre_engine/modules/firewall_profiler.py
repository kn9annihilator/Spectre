import socket
import threading
from queue import Queue

# A thread-safe list to store the results
open_ports = []
# Lock to prevent race conditions when printing or appending to the list
print_lock = threading.Lock()

def scan_port(target_ip, port):
    """
    Attempts to connect to a single port and grab a banner if successful.
    """
    try:
        # Create a new socket object for IPv4 and TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout for the connection attempt to avoid long waits
        socket.setdefaulttimeout(1)

        # connect_ex returns 0 on success (port is open)
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            banner = ""
            try:
                # If port is open, try to receive 1024 bytes of data (the banner)
                banner = s.recv(1024).decode(errors='ignore').strip()
            except socket.error:
                # If no banner is received, we still know the port is open
                pass
            
            # Use a lock to safely append to our shared list
            with print_lock:
                port_info = {"port": port, "banner": banner}
                open_ports.append(port_info)
        
        # Close the socket connection
        s.close()

    except Exception:
        pass

def worker(q, target_ip):
    """
    Worker function for threads. Pulls a port from the queue and scans it.
    """
    while not q.empty():
        port = q.get()
        scan_port(target_ip, port)
        q.task_done()

def parse_ports(ports_str):
    """
    Parses a port string (e.g., "80,443,1000-1024") into a list of integers.
    """
    ports_to_scan = []
    # Split by comma for individual ports or ranges
    parts = ports_str.split(',')
    for part in parts:
        if '-' in part:
            # It's a range, e.g., "1000-1024"
            start, end = map(int, part.split('-'))
            ports_to_scan.extend(range(start, end + 1))
        else:
            # It's a single port
            ports_to_scan.append(int(part))
    return ports_to_scan

def run_scan(target, ports_str, threads):
    """
    The main orchestrator for the port scan.
    
    Args:
        target (str): The target hostname or IP address.
        ports_str (str): The string representing ports to scan.
        threads (int): The number of threads to use.
        
    Returns:
        list: A list of dictionaries, where each dictionary represents an open port.
    """
    global open_ports
    open_ports = [] # Clear results from previous scans

    try:
        # Resolve hostname to IP address. This is done once to avoid repeated DNS lookups.
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Error: Could not resolve hostname '{target}'")
        return []

    # Create a queue and fill it with the ports to be scanned
    q = Queue()
    for port in parse_ports(ports_str):
        q.put(port)

    # Create and start the worker threads
    for _ in range(threads):
        thread = threading.Thread(target=worker, args=(q, target_ip))
        thread.daemon = True # Allows main program to exit even if threads are running
        thread.start()
    
    # Wait for all ports in the queue to be processed
    q.join()
    
    # Sort the results by port number for clean output
    return sorted(open_ports, key=lambda x: x['port'])