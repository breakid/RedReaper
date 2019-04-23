import binascii
from datetime import datetime as dt
from datetime import timedelta
from pprint import pprint
import hashlib
import json
import os
import sys


# Flag that controls where to print more verbose output to the screen
verbose = False

# Flag used to control the logging of debug information
DEBUG = False

#==============================================================================
#******                            Constants                             ******
#==============================================================================

# Used to timestamp log filename
START_TIME = dt.now()

# 'Pretty' date format
TIMEFORMAT_LOG = '%Y-%m-%d %H:%M:%S'

# Date format compatible with file naming limitations
TIMEFORMAT_FILE = '%Y-%m-%d_%H%M%S'



#==============================================================================
#******                        Logging Functions                         ******
#==============================================================================

def set_verbose():
  """Sets the verbose flag to True which forces more information to tbe 
  printed to the screen.
  
  """
  global verbose
  verbose = True



def log(msg, suppress=True):
  """Logs the specified message to a file and displays it to the user unless
  suppressed.
  
   Parameters:
    msg (str):        The message to be logged and displayed to the user
    suppress (bool):  Whether or not suppress display of the message on screen
                      Optional; default (True)
  
  """
  try:
    if verbose or not suppress:
      print(msg)
    
    if not os.path.exists('logs'):
      os.makedirs('logs')
    
    with open('logs/RedReaper_%s.log' % START_TIME.strftime(TIMEFORMAT_FILE), 'a') as log_file:
      log_file.write('[%s] %s\n' % (dt.now().strftime(TIMEFORMAT_LOG), msg))
  except Error as e:
    # Log that an error occurred while logging
    error(e, fatal = False)



def warn(msg, obj=None, suppress=False):
  """Logs a non-fatal warning message unless suppressed.
  
   Parameters:
    msg (str):        An error message to be logged and displayed to the user
    obj (obj):        A JSON object to be logged
                      Optional: default (None)
    suppress (bool):  Whether or not suppress display of the message on screen
                      Optional; default (True)
  """
  if obj is None:
    log('[!] WARN: %s' % msg, suppress=suppress)
  else:
    log('[!] WARN: %s\n%s' % (msg, json.dumps(obj)), suppress=suppress)



def error(msg, obj=None, fatal=True):
  """Logs an error message unless suppressed and optionally exits.
  
   Parameters:
    msg (str):    An error message to be logged and displayed to the user
    obj (obj):    A JSON object to be logged
                  Optional: default (None)
    fatal (bool): Whether the error should cause the script to exit
                  Optional; default (True)
  """
  
  if obj is None:
    log('[-] ERROR: %s' % msg, suppress=False)
  else:
    log('[-] ERROR: %s\n%s' % (msg, json.dumps(obj)), suppress=False)
  
  if fatal:
    sys.exit(1)



def debug(msg, obj=None):
  """Logs debugging information. Does not display on the screen.
  
   Parameters:
    msg (str): An error message to be logged and displayed to the user
    obj (obj): A JSON object to be logged
               Optional: default (None)
  """
  if DEBUG:
    if obj is None:
      log('[*] DEBUG: %s' % msg)
    else:
      log('[*] DEBUG: %s\n%s' % (msg, json.dumps(obj)))



#==============================================================================
#******                         Domain Functions                         ******
#==============================================================================

def load_domains():
  """Loads DNS_domain to NT_domain mapping from a resource file."""
  # Dictionary mapping DNS domains to NT domains
  domain_map = {}
  domain_map_file = 'resources\\domain_map.json'

  if os.path.exists(domain_map_file):
    with open(domain_map_file, 'r') as in_file:
      domain_map = json.load(in_file)
      
      # Ensure all DNS and NT domains are uppercase
      for key, value in domain_map.items():
        domain_map[key.upper()] = value.upper()
  
  return domain_map



def save_domains(domain_map):
  """Saves a DNS_domain to NT_domain mapping to a resource file.
  
   Parameters:
    dict: Dictionary mapping DNS domains to NT domains.
  """
  domain_map_file = 'resources\\domain_map.json'
  with open(domain_map_file, 'w') as out_file:
    json.dump(domain_map, out_file)



def get_tld(dns_domain):
  """Returns the last component of a DNS domain name.
  
  Parameters:
    dns_domain (str): A DNS domain in dot-notation (e.g., SGC.HWS.MIL)
    
  Returns:
    str: The last component of a DNS domain name
  """
  return dns_domain.split('.')[-1].upper()



#==============================================================================
#******                       Credential Functions                       ******
#==============================================================================

def get_ntlm(plaintext):
  """Calculates the NTLM hash for a given plaintext.
  
   Parameters:
    plaintext (str): A plaintext password
  
  Returns:
    str: The NTLM hash for the given plaintext
  """
  return binascii.hexlify(hashlib.new('md4', plaintext.encode('utf-16le')).digest()).upper()

def merge_cred(cred1, cred2):
  """Merges two credential objects or replaces one with the other, if 
  appropriate.
  
   Parameters:
    cred1 (dict): A credential object
    cred2 (dict): A credential object
  """
  # TODO: Update to account for collected_at

  # All credential entries should have at least NTLM
  #   - hashdump -> NTLM
  #   - lsadump -> NTLM
  #   - dcsync -> NTLM, AES128, AES256
  #   - logonpasswords -> NTLM OR plaintext, NTLM
  if cred1['ntlm'] != cred2['ntlm']:
    # If the new NTLM doesn't match the old NTLM, the user changed their 
    # password, overwrite the old data
    
    # Maintain credential number, if appliable
    if 'num' in cred1:
      cred2['num'] = cred1['num']
    
    cred1 = cred2
  else:
    # NTLMs match, merge data
    cred2['source_history'] = cred1['source_history'] + '; ' + cred2['source_history']
    cred1.update(cred2)



def merge_creds(dict1, dict2):
  """Merges two dictionaries containing credentials appropriately to avoid 
  overwriting important data.
    
   Parameters:
    dict1 (dict): A dictionary containing credentials
    dict2 (dict): A dictionary containing credentials
  """
  cred_num = len(dict1.keys())
  
  for user in dict1:
    if user in dict2:
      merge_cred(dict1[user], dict2[user])
      del dict2[user]
  
  # Add any new credentials to dict1
  for user, data in dict2.items():
    dict1[user] = data



def enrich_creds(cred, technique, host, tstamp):
  """Adds type, collected_at, collected_from, source_history, and comment to a
  credential object to a credential object and generates a qualified 
  (realmified) username as an ID
  
  Parameters:
    cred (dict):  A credential object
    host (dict):  The host object from which the credential was collected
    tstamp (str): The datetime when the credentials where collected
                  Format: 'YYYY-MM-DD HH:mm:ss'
  
  Returns:
    dict: A dictionary where the key is a qualified (realmified) username and
          the value is the enhanced credential object
  """
  id = '\\'.join([cred['realm'], cred['username']])

  cred['type'] = 'local' if cred['realm'] == host['hostname'] else 'domain'
  cred['collected_at'] = tstamp
  cred['collected_from'] = host['id']
  cred['source_history'] = '%s on %s @ %s' % (technique, host['id'], tstamp)
  if 'comment' not in cred: cred['comment'] = ''
  
  return {id: cred}






#==============================================================================
#******                        Utility Functions                         ******
#==============================================================================

def init_aggregator_dict(dict1, host, dns_domain='UNKNOWN'):
  """Initializes a dictionary such that it segregates data by network and DNS
  domain.
  
   Parameters:
    dict1 (dict):     The dictionary to be initialized
                      The dictionary is passed by reference and WILL be 
                      modified
    host (dict):      A host object, used to determine the appropriate network
    dns_domain (str): The DNS domain used to segregate data
                      Optional; default ('UNKNOWN')
                      If not provided, the script will use the given host's 
                      DNS domain, if available
  
  Returns:
    dict: A subset of dict1 representing the DNS domain
  """
  network = host['network']
  
  # Log data under the collected host's DNS domain (if possible), unless explicitly overridden
  if dns_domain == 'UNKNOWN' and 'dns_domain' in host:
    dns_domain = host['dns_domain'] 
  
  if network not in dict1:
    dict1[network] = {}
    
  if dns_domain not in dict1[network]:
    dict1[network][dns_domain] = {}
  
  return dict1[network][dns_domain]



def timestamp_to_filename(tstamp):
  """Converts a 'pretty' timestamp to one that can be used as a filename.
  
  Parameters:
    tstamp (str): A 'pretty' timestamp; format: "YYYY-MM-DD HH:mm:ss"
  
  Returns:
    str: A filename-compatible timestamp; format: "YYYY-MM-DD_HHmmss"
    
  """
  return tstamp.replace(':', '').replace(' ', '_')



def convert_nt_time(nt_time):
  """Converts Windows NT time value to a human-readable datetime value.
  
  Parameters:
    nt_time (str): A Windows NT time value

  Returns:
    str: A human-readable datetime value; format: "YYYY-MM-DD HH:mm:ss"
  """
  nt_time = nt_time.strip()
  
  if nt_time == '':
    return ''
  
  try:
    nt_time = int(nt_time)
    
    if nt_time == 0:
      return ''
      
    epoch_start = dt(year=1601, month=1, day=1)
    seconds_since_epoch = nt_time / 10 ** 7
    timestamp = epoch_start + timedelta(seconds=seconds_since_epoch)
    
  except ValueError:
    timestamp = dt.strptime(nt_time.split(".")[0], "%Y%m%d%H%M%S")

  return timestamp.strftime('%Y-%m-%d %H:%M:%S')



def convert_uac(uac):
  """Converts a numeric Active Directory userAccountControl value to a 
  human-readable string.
  
  Parameters:
    uac (str):  A string containing a numeric Active Directory 
                userAccountControl value

  Returns:
    str: A human-readable string representation of the given userAccountControl value
  """
  if uac.strip() == '':
    return ''
  
  # Source: https://jackstromberg.com/2013/01/useraccountcontrol-attributeflag-values/
  UAC_FLAGS = {
    '0x0001': "SCRIPT",
    '0x0002': "ACCOUNTDISABLE",
    '0x0008': "HOMEDIR_REQUIRED",
    '0x0010': "LOCKOUT",
    '0x0020': "PASSWD_NOTREQD",
    '0x0040': "PASSWD_CANT_CHANGE",
    '0x0080': "ENCRYPTED_TEXT_PWD_ALLOWED",
    '0x0100': "TEMP_DUPLICATE_ACCOUNT",
    '0x0200': "NORMAL_ACCOUNT",
    '0x0202': "Disabled Account",
    '0x0220': "Enabled, Password Not Required",
    '0x0222': "Disabled, Password Not Required",
    '0x0800': "INTERDOMAIN_TRUST_ACCOUNT",
    '0x1000': "WORKSTATION_TRUST_ACCOUNT",
    '0x2000': "SERVER_TRUST_ACCOUNT",
    '0x10000': "DONT_EXPIRE_PASSWORD",
    '0x10200': "Enabled, Password Doesn't Expire",
    '0x10202': "Disabled, Password Doesn't Expire",
    '0x10222': "Disabled, Password Doesn't Expire & Not Required",
    '0x20000': "MNS_LOGON_ACCOUNT",
    '0x40000': "SMARTCARD_REQUIRED",
    '0x40200': "Enabled, Smartcard Required",
    '0x40202': "Disabled, Smartcard Required",
    '0x40222': "Disabled, Smartcard Required, Password Not Required",
    '0x50202': "Disabled, Smartcard Required, Password Doesn't Expire",
    '0x50222': "Disabled, Smartcard Required, Password Doesn't Expire & Not Required",
    '0x80000': "TRUSTED_FOR_DELEGATION",
    '0x82000': "Domain controller",
    '0x100000': "NOT_DELEGATED",
    '0x200000': "USE_DES_KEY_ONLY",
    '0x400000': "DONT_REQ_PREAUTH",
    '0x800000': "PASSWORD_EXPIRED",
    '0x1000000': "TRUSTED_TO_AUTH_FOR_DELEGATION",
    '0x04000000': "PARTIAL_SECRETS_ACCOUNT"
  }
  
  flags = []
  
  for flag in UAC_FLAGS:
    # Perform a bitwise XOR to determine if the flag is part of the UAC value
    if int(uac) ^ int(flag, 16) == 0:
      flags.append(UAC_FLAGS[flag])
  
  return '\n'.join(sorted(flags))