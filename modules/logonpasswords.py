import re
from pprint import pprint
from _utils import *


# Example:
# Authentication Id : 0 ; 132054 (00000000:000203d6)
# Session           : Interactive from 1
# User Name         : Administrator
# Domain            : SGC
# Logon Server      : SGCDC001
# Logon Time        : 3/15/2019 9:09:16 PM
# SID               : S-1-5-21-60804857-299774370-1069655206-500
# 	msv :	
# 	 [00000003] Primary
# 	 * Username : Administrator
# 	 * Domain   : SGC
# 	 * NTLM     : b1f01d13cdb6fcf1792153512dcc0084
# 	 * SHA1     : db29308995869d1b0ab77eeb0777f0751e5734d2
# 	 [00010000] CredentialKeys
# 	 * NTLM     : b1f01d13cdb6fcf1792153512dcc0084
# 	 * SHA1     : db29308995869d1b0ab77eeb0777f0751e5734d2
# 	tspkg :	
# 	wdigest :	
# 	 * Username : Administrator
# 	 * Domain   : SGC
# 	 * Password : Inthemiddleofmybackswing?
# 	kerberos :	
# 	 * Username : Administrator
# 	 * Domain   : SGC.HWS.MIL
# 	 * Password : (null)
# 	ssp :	KO
# 	credman :	
# 
LOGON_SESSION_PATT = re.compile('Authentication Id :.+?User Name[ ]+: (?P<username>.*?)\nDomain[ ]+: (?P<realm>.*?)\n.+?SID[ ]+: (?P<sid>.*?)\n(?P<package_data>.+?)\n\n', re.DOTALL)


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
USER_DOMAIN_PASSWORD_PATTERN = re.compile('.+\* Username : (?P<username>.+)\n.+\* Domain[ ]+: (?P<realm>.+)\n.+\* Password[ ]+: (?P<plaintext>.+)\n')

REALM_BLACKLIST = ['', '(NULL)', 'NT AUTHORITY', 'WINDOW MANAGER', 'FONT DRIVER HOST']


# Load DNS_domain to NT_domain mapping from resource file
domain_map = load_domains()


def update_missing_info(cred, data):
  # Replace the session username with the package username, if the session one is null
  if cred['username'] == '(null)':
    cred['username'] = data['username']
  
  # Replace the session realm with the package realm, if the session realm is on the blacklist
  if cred['realm'] in REALM_BLACKLIST:
    cred['realm'] = data['realm'].upper()
    
  # Calculate NTLM from plaintext
  if 'plaintext' in data:
    cred['ntlm'] = get_ntlm(data['plaintext'])


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
  
  output = output.lstrip()
  
  if output.startswith('Authentication Id : '):
    creds = {}
    domain_dict = init_aggregator_dict(global_vars['credentials'], host)
    
    for session in LOGON_SESSION_PATT.finditer(output):
      data = session.groupdict()
      
      # Initialize logon session cred object
      # Normalize capitalization of the realm
      # Save the username, unless it's 'DWM-1' (Window Manager) in which case set it to null so it's overridden later
      # Derive the RID from the SID, if possible
      cred = {
        'realm': data['realm'].upper(),
        'username': data['username'] if data['username'] != 'DWM-1' else '(null)',
        'rid': data['sid'].split('-')[-1] if len(data['sid']) > 39 else ''
      }
      
      for match in MSV_PATTERN.finditer(data['package_data']):
        d = match.groupdict()
        
        if d['ntlm'] == '(null)':
          continue
        
        cred['ntlm'] = d['ntlm'].upper()
        update_missing_info(cred, d)
      
      for match in USER_DOMAIN_PASSWORD_PATTERN.finditer(data['package_data']):
        d = match.groupdict()
        
        if d['plaintext'] == '(null)':
          continue
        
        cred['plaintext'] = d['plaintext']
        update_missing_info(cred, d)
        
        # If logonpasswords returns the DNS domain rather than the NT domain, correct the realm
        if d['realm'] in domain_map:
          dns_domain = d['realm']
          
          if cred['realm'] == dns_domain:
            cred['realm'] = domain_map[dns_domain]
          
          # NOTE: Originally I was going to save this under another domain if it was different, but these are cached credentials so even if it's from a different domain, it still has access to resources on this host in the current domain and so is worth recording in association with the current domain; in fact, this would be an interesting finding...
          #tmp_domain_dict = init_aggregator_dict(global_vars['credentials'], host, dns_domain)
          #merge_creds(tmp_domain_dict, enrich_creds(cred, 'logonpasswords', host, tstamp))
      
      # Only save creds with useful data
      # All creds should have NTLM whether directly extracted or calculated from plaintext
      if 'ntlm' in cred:
        id = cred['realm'] + '\\' + cred['username']
        
        # Logon sessions are in reverse chronological order, only get the first (i.e., most recent) for each user, unless the first was missing a plaintext password that is in a subsequent entry...but only if the NTLMs match (otherwise, the plaintext password is no longer correct)
        # NOTE: Do this check after all potential manipulation of the realm and username
        if id in creds and cred['ntlm'] == creds[id]['ntlm'] and 'plaintext' in cred and 'plaintext' not in creds[id]:
          merge_cred(creds, enrich_creds(cred, 'logonpasswords', host, tstamp))
        elif id not in creds:
          creds.update(enrich_creds(cred, 'logonpasswords', host, tstamp))
    
    # Merge the final set of credentials into the domain dictionary
    merge_creds(domain_dict, creds)
    
    # Save raw text output to a file in case unparsed data is required
    filepath = '..\\..\\credentials\\logonpasswords\\%s_%s_logonpasswords.txt' % (host['hostname'], timestamp_to_filename(tstamp))
    host['text'][filepath] = output
    
    return True
  
  return False