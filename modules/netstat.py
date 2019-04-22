from pprint import pprint
import re

# Example:
#  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
#  TCP    [::1]:8307             [::1]:56082            ESTABLISHED     5824
#  UDP    0.0.0.0:500            *:*                                    3916
#  UDP    [fe80::1e7:43fd:463b:ff53%18]:1900  *:*                                    8184
ENTRY_PATT = re.compile('  (?P<protocol>[TCUDP]{3})[ ]+\[?(?P<address_local>[a-f\d\.\:%]+)\]?:(?P<port_local>\d+)[ ]+\[?(?P<address_remote>[a-f\d\.\:%\*]+)\]?:(?P<port_remote>[\d\*]+)[ ]+(?P<state>[A-Z_]*)[ ]*(?P<pid>\d+)')

# Maps port numbers to human-readable service names
SVC_MAP = {
  23: 'telnet',
  25: 'smtp',
  53: 'dns',
  80: 'http',
  88: 'kerberos',
  135: 'rpc',
  389: 'ldap',
  443: 'https',
  445: 'smb',
  636: 'ldaps',
  3389: 'rdp',
  5985: 'winrm_http',
  5986: 'winrm_https',
  8080: 'http_alt',
  8443: 'https_alt'
}


def get_process_list(host):
  """Loads the most recent process list from the given host.
  
  Parameters:
    host (dict): The host object from which the netstat came
  
  Returns:
    dict: A dictionary mapping PIDs to process names and descriptions
  """
  procs = {}

  if 'ps' in host:
    most_recent = max(host['ps']['data'].keys())
    
    for proc in host['ps']['data'][most_recent]:
      procs[proc['pid']] = {'process_name': proc['process_name']}
      
      if 'desc' in proc:
        procs[proc['pid']]['proc_desc'] = proc['desc']
  
  return procs



def parse_output(host, tstamp, output, global_vars):
  """Parses netstat output to store network connections associated with the
  given host, correlates network connection PIDs with a process list (if 
  available), and performs rudimentary service/function detection.
  
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
  
  # Start with the quick and easy identifier but fall back to the more expensive but more reliable search in case something in the output format changes
  if output.startswith('\nActive Connections\n') or ENTRY_PATT.search(output):
    services = []
    net_connections = []
    procs = get_process_list(host)
    
    for line in output.split('\n'):
      match = ENTRY_PATT.match(line)
      
      if match is not None:
        row = match.groupdict()
        
        if '.' in row['address_local']:
          row['version'] = 'IPv4'
        else:
          row['version'] = 'IPv6'
        
        pid = row['pid']
        
        if pid in procs:
          row.update(procs[pid])
        
        port = int(row['port_local'])
        
        if port in SVC_MAP:
          services.append(SVC_MAP[port])
        
        net_connections.append(row)
    
    # Keep track of (unique) known services running on the host
    host['services'] = list(set(host['services'] + services))
    
    if 'netstat' not in host.keys():
      host['netstat'] = {}
      host['netstat']['fieldnames'] = ['version', 'protocol', 'address_local', 'port_local', 'address_remote', 'port_remote', 'state', 'pid', 'process_name', 'proc_desc']
      host['netstat']['data'] = {}
    
    host['netstat']['data'][tstamp] = net_connections
    
    return True
  
  return False
