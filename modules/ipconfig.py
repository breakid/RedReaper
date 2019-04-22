import re
from pprint import pprint
from _utils import *


DETECT_PATT = re.compile('Primary Dns Suffix[ \.]+?: (?P<dns_domain>.+?)\n')

# Matches a section of the ipconfig associated with a single NIC
NIC_PATT = re.compile('(?P<name>.+?)\n\n(?P<nic_data>.+?)\n\n', re.DOTALL)

# Matches one or more DNS servers
DNS_SERVER_PATT = re.compile('DNS Servers[ \.]+?:(.+)\n   [^ ]', re.DOTALL)


# Load DNS_domain to NT_domain mapping from resource file
domain_map = load_domains()


def parse_output(host, tstamp, output, global_vars):
  """Parses ipconfig output to populate NIC data related to a host.
  Vital for obtaining the DNS domain for a host.
  
  Parameters:
    host (dict):        An object representing the host from which the output
                        came
    tstamp (str):       The datetime when the output was received
                        Format: "YYYY-MM-DD HH:mm:ss"
    output (text):      A text output of a command
    global_vars (dict): A dictionary used to stored the parsed data
  
  Returns:
    bool: Whether the output type matched the current module
  """
  
  match = DETECT_PATT.search(output)
  
  if match is not None:
    data = match.groupdict()
    host['dns_domain'] = data['dns_domain'].upper()
    
    if host['dns_domain'] in domain_map:
      host['nt_domain'] = domain_map[host['dns_domain']]
    else:
      # Keep track of DNS domains that don't map to an NT domain, so we can 
      # prompt the user for them before writing output
      global_vars['missing_domains'].append(host['dns_domain'])
    
    nics = []
    
    for match in NIC_PATT.finditer(output):
      nic = {}
      data = match.groupdict()
      name = data['name'].strip()
      nic_data = data['nic_data']
      
      # Skip the ipconfig header
      if name == 'Windows IP Configuration':
        continue
      
      i = 0
      lines = nic_data.split('\n')
      
      # NOTE: Since the existence of lines in ipconfig varies based on the configuration, this doesn't lend itself well to regex; parse it line by line
      while i < len(lines):
        line = lines[i].strip()
        i += 1
      
        if 'DNS Suffix' in line:
          nic['dns_suffix'] = line.split(':')[1].lstrip().upper()
        elif 'Description' in line:
          nic['desc'] = line.split(': ')[1]
        elif 'Physical Address' in line:
          nic['mac'] = line.split(': ')[1]
        elif 'IPv6 Address' in line:
          nic['ip_v6'] = line.split(': ')[1].replace('(Preferred)', '')
        elif 'IPv4 Address' in line:
          nic['ip_v4'] = line.split(': ')[1].replace('(Preferred)', '')
        elif 'Subnet Mask' in line:
          nic['subnet_mask'] = line.split(': ')[1]
        elif 'Default Gateway' in line:
          nic['default_gateway'] = line.split(': ')[1]
        elif 'Lease Obtained' in line:
          nic['dhcp_lease_obtained'] = line.split(': ')[1]
        elif 'Lease Expires' in line:
          nic['dhcp_lease_expires'] = line.split(': ')[1]
        elif 'DHCP Server' in line:
          nic['dhcp_server'] = line.split(': ')[1]
        elif 'Media State' in line:
          nic['status'] = line.split(': ')[1]
        
        # Find, parse, and trim list of DNS servers
        dns_servers = DNS_SERVER_PATT.search(nic_data)
        
        if dns_servers is not None:
          dns_servers = [svr.strip() for svr in dns_servers.group(1).split('\n')]
          
          if len(dns_servers) > 0:
            nic['dns_servers'] = dns_servers
      
      # Append nic to nics if not empty
      if len(nic) > 0:
        nics.append(nic)
    
    host['nics'] = nics
    
    return True
    
  return None
