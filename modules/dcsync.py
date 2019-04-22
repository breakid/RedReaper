import re
from _utils import *


PATTERN = re.compile("\[DC\] '(?P<dns_domain>.*)' will be the domain.*\[DC\] '(?P<realm>.*?)\\\\(?P<username>.*?)' will be the user account.*Object Relative ID   : (?P<rid>\d+).*Hash NTLM: (?P<ntlm>[0-9a-f]{32}).*aes256_hmac       \(4096\) : (?P<aes256>[0-9a-f]{64}).*aes128_hmac       \(4096\) : (?P<aes128>[0-9a-f]{32})", re.DOTALL)


def parse_output(host, tstamp, output, global_vars):
  """Parses credentials from dcsync output.
  
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
  
  if PATTERN.search(output) is not None:
    data = PATTERN.search(output).groupdict()
    data['ntlm'] = data['ntlm'].upper()
    data['aes128'] = data['aes128'].upper()
    data['aes256'] = data['aes256'].upper()
    #data['comment'] = 'dcsync'
    
    # Parse the DNS domain from the output because it does not have to match 
    # that of the collection host
    dns_domain = data['dns_domain']
    del data['dns_domain']
    
    domain_dict = init_aggregator_dict(global_vars['credentials'], host, dns_domain)
    merge_creds(domain_dict, enrich_creds(data, 'dcsync', host, tstamp))
    
    # Save raw text output to a file in case unparsed data is required
    filepath = '..\\..\\..\\%s\\credentials\\dcsync\\%s_%s_%s_dcsync.txt' % (dns_domain, data['realm'], data['username'], timestamp_to_filename(tstamp))
    host['text'][filepath] = output
    
    return True
    
  return False