import re
from pprint import pprint
from _utils import *

# IMPORTANT: Requires dsqueries to be output in *LIST* format and contain the ADsPath attribute!
# ASSUMPTION: Output follows the order of the native dsquery (beginning with objectclass and ending with ADsPath)

DETECT_PATT = re.compile('ADsPath: ')

# Used to capture all of the attributes of a single object for iterative processing
OBJ_PATT = re.compile('(?P<object>.*?ADsPath: .*?)\n', re.DOTALL)

KV_PATT = re.compile('^(?P<key>.*?): (?P<value>.*)$')

# Used to extract the DNS domain from the Domain Component of an ADsPath (useful for accurate organization of data when querying a remote domain)
ADSPATH_PATT = re.compile('DC=(?P<dc>.*)')


# Load DNS_domain to NT_domain mapping from resource file
domain_map = load_domains()


def parse_output(host, tstamp, output, global_vars):
  """Parses Active Directory data from dsquery output.
  
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
  
  # NOTE: The only attribute all dsqueries must have is ADsPath, therefore use it to identify dsquery output
  if DETECT_PATT.search(output) is not None:
    # Save the DNS domain so we can map to the NT domain and include it in the filename when writing the raw text output to a file
    # ASSUMPTION: The dns_domain will be the same for all objects in a single query, so the last entry should be representative of all objects
    dns_domain = 'unknown'
    
    # ASSUMPTION: Group has no uniquely distinguishing attributes, so if nothing else matches, it's probably a group
    # ASSUMPTION: All objects in a single query are of the same type, so the type of the last entry should be representative of all objects
    obj_type = 'groups'
    
    # Split attributes into discrete objects
    for match in OBJ_PATT.finditer(output):
      obj = {}
      object_data = match.groupdict()['object']
      
      # Iterate through each line, parse each key/value pair
      for line in object_data.split('\n'):
        data = KV_PATT.search(line)
      
        if data is not None:
          data = data.groupdict()
          key = data['key'].lower()
          value = data['value'].strip()
          
          # Gracefully handle multiples of the same key
          if key in obj.keys():
            obj[key] = obj[key] + '\n' + value
          else:
            obj[key] = value
          #  obj[key].append(value)
          #else:
          #  obj[key] = [value]
      
      # Auto-detect object type based on unique attributes
      if 'displayname' in obj:
        obj_type = 'gpos'
      elif 'gplink' in obj:
        obj_type = 'ous'
      elif 'operatingsystem' in obj: #'objectclass' in obj and 'computer' in obj['objectclass']:
        obj_type = 'computers'
      elif 'pwdlastset' in obj: #'objectclass' in obj and 'user' in obj['objectclass']:
        obj_type = 'users'
      elif 'flatname' in obj:
        obj_type = 'trusts'
      
      # Bail if the object type isn't one being tracked
      if obj_type not in global_vars:
        warn('Unsupported dsquery type (%s)' % obj_type)
        return True
      
      # Gracefully determine name of object to use as the ID in the dictionary
      name = ''
      
      if 'name' in obj:
        name = obj['name']
      elif 'dnshostname' in obj:
        name = obj['dnshostname'].split('.')[0]
      elif 'flatname' in obj:
        name = obj['flatname']
      else:
        warn('Active Directory object with no name', obj)
        # Name is required to store the object, if there isn't one, skip it
        continue
      
      if 'adspath' in obj:
        dns_domain = ADSPATH_PATT.search(obj['adspath'])
        dns_domain = dns_domain.groupdict()['dc'].replace(',DC=', '.').upper()
        
        # Save realm data so the qualified username can be determined when linking creds during post-processing
        realm = dns_domain
        
        if realm in domain_map:
          realm = domain_map[realm]
        
        obj['realm'] = realm
      
      # Construct the necessary dictionary structure (to match the directory structure) and save the object
      domain_dict = init_aggregator_dict(global_vars[obj_type], host, dns_domain)
      domain_dict[name] = obj
    
    filepath = '..\\..\\..\\%s\\dsquery\\%s_%s_%s.txt' % (dns_domain, realm, timestamp_to_filename(tstamp), obj_type)
    host['text'][filepath] = output
    
    return True
    
  return False
