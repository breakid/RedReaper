import re
from _utils import *


# Matches the beginning of the output from a "dnscmd /zoneprint" command
DETECT_PATT = re.compile(';  Zone:[ ]*.*\n;  Server:[ ]*')

# Regex for A records
A_REC_PATT = re.compile('^(?P<hostname>[a-zA-Z0-9\-]*?)\s.+?\s?\d*\sA\s(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$')
  
# Regex for CNAME records
CNAME_REC_PATT = re.compile('^(?P<alias>[a-zA-Z0-9\-]*?)\s[.+?\s]?\d*\sCNAME\s(?P<fqdn>[a-zA-Z0-9\-\.]*)$')


def parse_output(host, tstamp, output, global_vars):
  """Reads and parses output from "dnscmd /zoneprint" to create a 
  dictionary of hostnames and their associated IPs, CNAMEs, and FQDNs.
  
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
  
  if DETECT_PATT.search(output) is not None:
    zone = ''
    
    # Construct the necessary dictionary structure (to match the directory structure) and save the object
    hostname_map = init_aggregator_dict(global_vars['dns_info'], host)
    
    
    for line in output.split('\n'):
      line = line.strip()
      
      if ';  Zone:' in line:
        zone = line.split(':')[1].strip().upper()
      
      a_rec = A_REC_PATT.search(line)
    
      if a_rec is not None:
        a_rec = a_rec.groupdict()
        
        hostname = a_rec['hostname'].upper()
        fqdn = '%s.%s' % (hostname, zone)
        ip = a_rec['ip']
        
        # Skip FORESTDNSZONES and DOMAINDNSZONES (not sure what these are for)
        if hostname.endswith('DNSZONES'):
          continue
    
        # Save the IP in a list to gracefully handle multiple IPs per hostname
        if hostname in hostname_map:
          hostname_map[hostname]['ip'].append(ip)
        else:
          hostname_map[hostname] = {
            'hostname': hostname,
            'ip': [ip],
            'fqdn': [fqdn],
            'cname': []
          }
          
        global_vars['dns_lookup'][fqdn] = ip
      else:
        cname = CNAME_REC_PATT.search(line)
        
        if cname is not None:
          cname = cname.groupdict()
          
          fqdn = cname['fqdn'].strip('.').upper()
          hostname = fqdn.split('.')[0]
          alias = cname['alias'].upper()
          
          # Save the CNAME and FQDN in lists to gracefully handle multiples
          if hostname in hostname_map:
            hostname_map[hostname]['fqdn'].append(fqdn)
            hostname_map[hostname]['cname'].append(alias)
          else:
            #print('[-] ERROR: CNAME without A record...is this even possible?')
            hostname_map[hostname] = {
              'hostname': hostname,
              'ip': [],
              'fqdn': [fqdn],
              'cname': [alias]
            }
          
          global_vars['dns_lookup'][fqdn] = ip
    
    # Save raw text output to a file in case unparsed data is required
    filepath = '..\\..\\dns\\{0}_{1}_zoneprint.txt'.format(zone, timestamp_to_filename(tstamp))
    host['text'][filepath] = output
    
    return True
  
  return False