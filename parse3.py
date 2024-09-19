import xml.etree.ElementTree as ET
from pymetasploit3.msfrpc import MsfRpcClient
import json
from datetime import datetime
import time
import logging
import sys
import signal

# Set up logging to display in CLI
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Global flag for graceful shutdown
shutdown_flag = False

def signal_handler(signum, frame):
    global shutdown_flag
    logger.warning("Received interrupt signal. Initiating graceful shutdown...")
    shutdown_flag = True

signal.signal(signal.SIGINT, signal_handler)

def parse_nmap_xml(xml_file):
    logger.info(f"Parsing Nmap XML file: {xml_file}")
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    results = []
    
    for host in root.findall('./host'):
        ip = host.find('./address[@addrtype="ipv4"]').get('addr')
        
        os_elem = host.find('./os/osmatch')
        os_info = os_elem.get('name') if os_elem is not None else "Unknown"
        
        host_info = {
            "ip": ip,
            "os": os_info,
            "ports": []
        }
        
        for port in host.findall('./ports/port'):
            port_id = port.get('portid')
            service = port.find('service')
            if service is not None:
                service_name = service.get('name')
                version = service.get('version', 'Unknown')
                
                host_info["ports"].append({
                    "port": port_id,
                    "service": service_name,
                    "version": version,
                    "exploits": []
                })
        
        results.append(host_info)
    
    logger.info(f"Parsed {len(results)} hosts from Nmap XML")
    return results

def connect_to_msfrpc(password, host='127.0.0.1', port=55553):
    logger.info(f"Connecting to Metasploit RPC on {host}:{port}")
    try:
        client = MsfRpcClient(password, server=host, port=port, ssl=False)
        logger.info("Successfully connected to Metasploit RPC")
        return client
    except Exception as e:
        logger.error(f"Failed to connect to Metasploit RPC: {str(e)}")
        raise

def get_os_family(os_info):
    os_info = os_info.lower()
    if 'windows' in os_info:
        return 'windows'
    elif 'linux' in os_info:
        return 'linux'
    elif 'mac' in os_info or 'darwin' in os_info:
        return 'osx'
    else:
        return 'unknown'

def is_exploit_compatible(module, os_family):
    exploit_fullname = module.fullname.lower()
    
    # List of OS families to check against
    os_families = ['windows', 'linux', 'osx', 'android', 'ios', 'solaris', 'freebsd', 'netbsd', 'openbsd', 'aix', 'hpux', 'irix']
    
    # If the exploit fullname contains any OS family other than the target, it's not compatible
    for os in os_families:
        if os in exploit_fullname and os != os_family:
            return False
    
    # If the exploit fullname contains the target OS family, it's compatible
    if os_family in exploit_fullname:
        return True
    
    # If no OS is mentioned in the exploit fullname, consider it potentially compatible
    return not any(os in exploit_fullname for os in os_families)

def find_exploits(client, service, version, os_family):
    global shutdown_flag
    logger.info(f"Searching exploits for {service} {version} on {os_family}")
    try:
        search_results = client.modules.search(service)
        exploits = [m for m in search_results if m['type'] == 'exploit' and service.lower() in m['name'].lower()]
        
        detailed_exploits = []
        for exploit in exploits:
            if shutdown_flag:
                logger.warning("Shutdown requested. Stopping exploit search.")
                break
            try:
                module = client.modules.use('exploit', exploit['fullname'])
                
                if is_exploit_compatible(module, os_family):
                    logger.info(f"Compatible exploit found: {exploit['fullname']}")
                    detailed_exploits.append({
                        "name": exploit['name'],
                        "fullname": exploit['fullname'],
                        "description": module.description,
                        "rank": module.rank,
                        "references": module.references,
                        "targets": module.targets
                    })
            except Exception as e:
                logger.error(f"Error processing exploit {exploit['fullname']}: {str(e)}")
        
        logger.info(f"Found {len(detailed_exploits)} compatible exploits for {service} {version} on {os_family}")
        return detailed_exploits
    except Exception as e:
        logger.error(f"Error searching exploits for {service} {version}: {str(e)}")
        return []

def main():
    logger.info("Starting Nmap and Metasploit integration script")
    
    nmap_file = 'nmap_scan.xml'
    msf_password = 'yourpassword'  # Replace with your actual password
    
    try:
        parsed_data = parse_nmap_xml(nmap_file)
        client = connect_to_msfrpc(msf_password)
        
        for host in parsed_data:
            if shutdown_flag:
                logger.warning("Shutdown requested. Stopping host processing.")
                break
            os_family = get_os_family(host['os'])
            logger.info(f"Processing host: {host['ip']} (OS: {host['os']}, Family: {os_family})")
            for port_info in host['ports']:
                if shutdown_flag:
                    logger.warning("Shutdown requested. Stopping port processing.")
                    break
                logger.info(f"Searching exploits for {port_info['service']} {port_info['version']} on {os_family}")
                port_info['exploits'] = find_exploits(client, port_info['service'], port_info['version'], os_family)
                time.sleep(1)  # Avoid overwhelming the Metasploit RPC server
        
        output = {
            "scan_date": datetime.now().isoformat(),
            "nmap_file": nmap_file,
            "results": parsed_data
        }
        
        with open('nmap_metasploit_results.json', 'w') as f:
            json.dump(output, f, indent=2)
        
        logger.info("Results have been written to nmap_metasploit_results.json")
        print("Script execution completed. Check nmap_metasploit_results.json for results.")
    
    except KeyboardInterrupt:
        logger.warning("KeyboardInterrupt received. Shutting down...")
    except Exception as e:
        logger.error(f"An error occurred during script execution: {str(e)}")

if __name__ == "__main__":
    main()
