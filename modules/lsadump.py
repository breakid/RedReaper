import re
from _utils import *

# Example: Domain : SGC / S-1-5-21-60804857-299774370-1069655206
DOMAIN_PATT = re.compile('Domain : (?P<realm>.+) /')

# Used to determine if the hashdump is from a DC
DETECT_DC_PATT = re.compile('User : krbtgt')

# Example:
# RID  : 000001f4 (500)
# User : Administrator
# LM   : 
# NTLM : b1f01d13cdb6fcf1792153512dcc0084
CRED_PATT = re.compile('RID  : .+\((?P<rid>\d+)\)\nUser : (?P<username>.+)\n.+\nNTLM : (?P<ntlm>[0-9-a-fA-F]{32})\n')


def parse_output(host, tstamp, output, global_vars):
  """Parses credentials from lsadump output.
  
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
  
  if DOMAIN_PATT.search(output) is not None:
    creds = {}
    
    # It's impossible to lsadump remotely, so the DNS domain should match that 
    # of the collection host
    domain_dict = init_aggregator_dict(global_vars['credentials'], host)
    
    realm = DOMAIN_PATT.search(output)
    realm = realm.groupdict()['realm']
    
    # If the hashump contains a krbtgt account, it's a DC; add the appropriate services to the host
    if DETECT_DC_PATT.search(output) is not None:
      host['services'] = list(set(host['services'] + ['ldap', 'kerberos']))
    
    for cred in CRED_PATT.finditer(output):
      data = cred.groupdict()
      data['ntlm'] = data['ntlm'].upper()
      data['realm'] = realm
      
      # Host is a domain controller; set the realm to the current domain
      #if 'ldap' in host['services']:
      #  if 'nt_domain' in host:
      #    id = '\\'.join([host['hostname'], data['username']])
          
      #    # Previous credential entries exist for this host, which has now been determined to be a DC; update all of these entries to reflect their domain status
      #    if id in global_vars['credentials']:
      #      prev_data = global_vars['credentials'][id]
      #      del global_vars['credentials'][id]
      #      prev_data.update(data)
      #      data = prev_data
          
      #    data['realm'] = host['nt_domain']
      
      merge_creds(domain_dict, enrich_creds(data, 'lsadump', host, tstamp))
    
    return True
  
  return False