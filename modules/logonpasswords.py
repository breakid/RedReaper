import re
from pprint import pprint
from _utils import *

# Example:
#  msv :
#   [00000003] Primary
#   * Username : Administrator
#   * Domain   : SGC
#   * NTLM     : b1f01d13cdb6fcf1792153512dcc0084
#   * SHA1     : db29308995869d1b0ab77eeb0777f0751e5734d2
#   [00010000] CredentialKeys
#   * NTLM     : b1f01d13cdb6fcf1792153512dcc0084
#   * SHA1     : db29308995869d1b0ab77eeb0777f0751e5734d2
MSV_PATTERN = re.compile('.+\* Username : (?P<username>.+)\n.+\* Domain[ ]+: (?P<realm>.+)\n.+\* NTLM[ ]+: (?P<ntlm>[0-9a-fA-F]{32})\n.+\* SHA1[ ]+: [0-9a-fA-F]{40}\n')

# Example:
#  wdigest :
#   * Username : Administrator
#   * Domain   : SGC
#   * Password : Inthemiddleofmybackswing?
WDIGEST_PATTERN = re.compile('.+\* Username : (?P<username>.+)\n.+\* Domain[ ]+: (?P<realm>.+)\n.+\* Password[ ]+: (?P<plaintext>.+)\n')


# Load DNS_domain to NT_domain mapping from resource file
domain_map = load_domains()


def parse_output(host, tstamp, output, global_vars):
  """Parses credentials from logonpasswords output.
  
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
  
  output = output.strip()

  if output.startswith('Authentication Id : '):
    creds = {}
    domain_dict = init_aggregator_dict(global_vars['credentials'], host)
    
    for match in MSV_PATTERN.finditer(output):
      d = match.groupdict()
      d['ntlm'] = d['ntlm'].upper()
      creds.update(enrich_creds(d, 'logonpasswords', host, tstamp))
    
    for match in WDIGEST_PATTERN.finditer(output):
      d = match.groupdict()
      
      # Ignore computer accounts and null passwords
      if '$' in d['username'] or d['username'] == '(null)' or d['plaintext'] == '(null)':
        continue
      
      # Calculate NTLM from plaintext
      if 'plaintext' in d:
        d['ntlm'] = get_ntlm(d['plaintext'])
      
      d['realm'] = d['realm'].upper()
        
      # If logonpasswords returns the DNS domain rather than the NT domain, correct the realm and make sure the credential is recorded under the proper DNS domain (in case it's different than the host's)
      if d['realm'] in domain_map:
        dns_domain = d['realm']
        d['realm'] = domain_map[d['realm']]
        
        tmp_domain_dict = init_aggregator_dict(global_vars['credentials'], host, dns_domain)
        merge_creds(tmp_domain_dict, enrich_creds(d, 'logonpasswords', host, tstamp))
      else:
        merge_creds(domain_dict, enrich_creds(d, 'logonpasswords', host, tstamp))
    
    # Save raw text output to a file in case unparsed data is required
    filepath = '..\\..\\credentials\\logonpasswords\\%s_%s_logonpasswords.txt' % (host['hostname'], timestamp_to_filename(tstamp))
    host['text'][filepath] = output
    
    return True
  
  return False