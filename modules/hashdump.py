import re
from pprint import pprint
from _utils import *


# Example: "Administrator:500:aad3b435b51404eeaad3b435b51404ee:b1f01d13cdb6fcf1792153512dcc0084:::"
DETECT_PATT = re.compile('.+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:*')
PATTERN = re.compile('(?P<username>.*?):(?P<rid>\d+):[0-9a-fA-F]{32}:(?P<ntlm>[0-9a-fA-F]{32}):*')

# Used to determine if the hashdump is from a DC
DETECT_DC_PATT = re.compile('krbtgt:')


def parse_output(host, tstamp, output, global_vars):
  """Parses credentials from hashdump output.
  
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
  
  lines = output.split('\n')
  
  # The first line of the output blob for a built-in hashdump is "received password hashes:", but use the second condition in case someone dumped hashes some other way such as a standalone pwdump (assumes that the second line will contain useful data)
  # Use match rather than search for better performance on large output
  # Don't use PATTERN so we don't consume the first match
  if len(lines) > 1 and (lines[0] == 'received password hashes:' or DETECT_PATT.match(lines[1]) is not None):
    creds = {}
    domain_dict = init_aggregator_dict(global_vars['credentials'], host)
    
    # If the hashump contains a krbtgt account, it's a DC; add the appropriate services to the host
    if DETECT_DC_PATT.search(output) is not None:
      host['services'] = list(set(host['services'] + ['ldap', 'kerberos']))
    
    for data in PATTERN.finditer(output):
      data = data.groupdict()
      data['ntlm'] = data['ntlm'].upper()
      data['realm'] = host['hostname']
      
      # Host is a domain controller; set the realm to the current domain
      #if 'ldap' in host['services']:
      #  if 'nt_domain' in host:
      #    id = '\\'.join([host['hostname'], data['username']])
          
          # Previous credential entries exist for this host, which has now been determined to be a DC; update all of these entries to reflect their domain status
      #    if id in domain_dict:
      #      print('DOMAIN CREDS: %s' % id)
            #prev_data = dict(domain_dict[id])
            #del domain_dict[id]
            #prev_data.update(data)
            #data = prev_data
            
      #      data = dict(domain_dict[id]).update(data)
      #      del domain_dict[id]
      #      pprint(data)
            
            
            
          
      #    data['realm'] = host['nt_domain']
      
      merge_creds(domain_dict, enrich_creds(data, 'hashdump', host, tstamp))
    
    return True
  
  return False