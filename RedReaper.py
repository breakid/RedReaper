#!/usr/bin/env python
#
# Copyright (C) 2019 Dan Breakiron
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from datetime import datetime as dt
from optparse import OptionParser
from pprint import pprint
import csv
import importlib
import json
import os
import re
import shutil
import sys

# Load shared utility functions from modules/_utils.py
from modules._utils import *


# Used to aggregate data across multiple beacon log files
aggregator_vars = {
  'commands': [],
  'computers': {},
  'credentials': {},
  'dns_info': {},
  'dns_lookup': {},
  'gpos': {},
  'groups': {},
  'hosts': {},
  'missing_domains': [],
  'num_creds': 0,
  'ous': {},
  'sessions': {},
  'trusts': {},
  'users': {}
}

# Used to keep track of which files have been processed to avoid duplicating work
processed_files = []

# Dictionary of loaded output parsing modules
modules = {}

# Dictionary mapping DNS domains to NT domains
domain_map = {}



#==============================================================================
#******                            Constants                             ******
#==============================================================================

DATESTAMP = dt.now().strftime('%Y-%m-%d')

# Format: ...\<engagement_name>\<network>\<year>\<month>\<day>\<implant>\<teamserver>\<host>\<beacon_id>.log
# Example: L:\VOIDWALKER\U\2019\03\26\cobaltstrike\10.4.100.201\10.4.10.101\beacon_3299.log
BEACON_FILEPATH_PATT = re.compile('.+[/\\\\]{1,2}(?P<network>.+?)[/\\\\]{1,2}(?P<year>\d{4})[/\\\\]{1,2}(?P<month>\d{2})[/\\\\]{1,2}(?P<day>\d{2})[/\\\\]{1,2}.+?[/\\\\]{1,2}(?P<teamserver>.+?)[/\\\\]{1,2}.+[/\\\\]{1,2}(?P<beacon_id>beacon_\d+)\.log')

# Example: 10/11 16:06:13 [metadata] beacon_83790 -> 172.16.10.23; computer: SGCWKS10246137; user: camile.wray; pid: 4652; os: Windows; version: 10.0; beacon arch: x86 (x64)
SESSION_INFO_PATT = re.compile('\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[metadata\] (?P<source>.*?) (?P<direction>[<\->]{2}) (?P<ip>.*?); computer: (?P<hostname>.*?); user: (?P<user>.*?); pid: (?P<pid>\d*?); os: (?P<os>.*?); version: (?P<kernel>.*?); beacon arch: (?P<beacon_arch>x\d{2}) \((?P<host_arch>x\d{2})\)')

# Example: 10/11 16:07:31 [input] <skelet0r> ps
INPUT_PATT = re.compile('\d{2}/\d{2} (?P<time>\d{2}:\d{2}:\d{2}) \[input\] <(?P<operator>.+?)> (?P<command>.+)')

# Read from an output tag until the next Cobalt Strike meta tag (don't consume the next tag in case it's another [output]); could be [input] or [output] (such as if multiple commands were queued)
# Example: 03/26 18:23:32 [output]
OUTPUT_PATT = re.compile('\d{2}/\d{2} (?P<time>\d{2}:\d{2}:\d{2}) \[output\]\n(?P<output>.+?)(?=\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[)', re.DOTALL)


FIELDNAMES = {
  'commands': ['teamserver', 'source', 'direction', 'ip', 'hostname', 'os', 'kernel', 'host_arch', 'beacon_arch', 'beacon_id', 'pid', 'user', 'timestamp', 'operator', 'command', 'line_number', 'filepath'],
  'computers': ['ip', 'dnshostname', 'operatingsystem', 'operatingsystemversion', 'operatingsystemservicepack', 'lastlogon', 'useraccountcontrol', 'description', 'memberof', 'primarygroupid', 'location', 'objectsid', 'adspath', 'ntlm', 'aes128', 'aes256', 'comment'],
  'credentials': ['num', 'type', 'realm', 'username', 'rid', 'plaintext', 'ntlm', 'aes128', 'aes256', 'collected_at', 'collected_from', 'comment', 'source_history'],
  'dns_info': ['hostname', 'ip', 'fqdn', 'cname'],
  'gpos': ['displayname', 'name', 'adspath'],
  'groups': ['samaccountname', 'name', 'userprinciplename', 'objectsid', 'primarygroupid', 'description', 'memberof', 'adspath'],
  'ous': ['name', 'managedby', 'description', 'gpos', 'gplink', 'adspath'],
  'trusts': ['trustdirection', 'flatname', 'trustpartner', 'adspath'],
  'users': ['samaccountname', 'name', 'userprinciplename', 'lastlogon', 'pwdlastset', 'useraccountcontrol', 'homedirectory', 'memberof', 'description', 'profilepath', 'objectsid', 'primarygroupid', 'adspath', 'plaintext', 'ntlm', 'aes128', 'aes256', 'comment']
}

# Art Source: https://www.asciiart.eu/mythology/grim-reapers
# Text Source: http://patorjk.com/software/taag/#p=display&f=Doom&t=RED%20REAPER
BANNER = """
  ===========================================================
  ______ ___________  ______ _____  ___  ______ ___________ 
  | ___ \  ___|  _  \ | ___ \  ___|/ _ \ | ___ \  ___| ___ \\
  | |_/ / |__ | | | | | |_/ / |__ / /_\ \| |_/ / |__ | |_/ /
  |    /|  __|| | | | |    /|  __||  _  ||  __/|  __||    / 
  | |\ \| |___| |/ /  | |\ \| |___| | | || |   | |___| |\ \ 
  \_| \_\____/|___/   \_| \_\____/\_| |_/\_|   \____/\_| \_|
  ===========================================================
                                                      
                      ...                             
                     ;::::;                           
                   ;::::; :;                          
                 ;:::::'   :;                         
                ;:::::;     ;.                        
               ,:::::'       ;           OOO\         
               ::::::;       ;          OOOOO\        
               ;:::::;       ;         OOOOOOOO       
              ,;::::::;     ;'         / OOOOOOO      
            ;:::::::::`. ,,,;.        /  / DOOOOOO    
          .';:::::::::::::::::;,     /  /     DOOOO   
         ,::::::;::::::;;;;::::;,   /  /        DOOO  
        ;`::::::`'::::::;;;::::: ,#/  /          DOOO 
        :`:::::::`;::::::;;::: ;::#  /            DOOO
        ::`:::::::`;:::::::: ;::::# /              DOO
        `:`:::::::`;:::::: ;::::::#/               DOO
         :::`:::::::`;; ;:::::::::##                OO
         ::::`:::::::`;::::::::;:::#                OO
         `:::::`::::::::::::;'`:;::#                O 
          `:::::`::::::::;' /  / `:#                  
           ::::::`:::::;'  /  /   `#                  
                                                      
"""



#==============================================================================
#******                             Getters                              ******
#==============================================================================

def get_session_id(teamserver, beacon_id):
  """Generates a unique session ID based on teamserver and beacon_id.
  
  The format of the ID can be changed within this function. Changing the 
  format *should not* have an effect as all IDs should be generated by 
  this function and therefore consistent within the script.
  
  Parameters:
    teamserver (str): An identifier for the teamserver (e.g., IP address)
    beacon_id (str):  The session ID of a beacon (e.g., beacon_3299)
    
  Returns:
    str: A unique session identifer
  """
  return '%s|%s' % (teamserver, beacon_id)



def get_host_by_session_id(session_id):
  """Returns the host object associated with the given session_id.
  
  Parameters:
    session_id (str): The ID of a session
    
  Returns:
    dict: The host object associated with the given session_id
          Returns 'None' if the session_id is not listed in sessions
  """
  if session_id in aggregator_vars['sessions']:
    host_id = aggregator_vars['sessions'][session_id]['host_id']
    
    if host_id in aggregator_vars['hosts']:
      return aggregator_vars['hosts'][host_id]
  
  return None



def get_host_by_name(hostname):
  """Returns a host object retrieved by hostname.
  
  Parameters:
    hostname (str): The name of a host
  
  Returns:
    dict: A host object
  
  """
  hosts = [host for id, host in aggregator_vars['hosts'].items() if host['hostname'] == hostname]
  
  if len(hosts) == 1:
    return hosts[0]
  elif len(hosts) > 1:
    error('Duplicate hostname detected: %s' % hostname)
  else:
    error('Unknown host: %s' % hostname)



def get_dns_domain_by_hostname(hostname):
  """Attempts to determine the DNS domain of a host using a list of FQDNs 
  derived from DNS info.
  
  Parameters:
    hostname (str): The name of the host whose DNS domain should be determined
    
  Returns:
    str: The DNS domain of the host; returns 'None' if not found
  
  """
  for fqdn in aggregator_vars['dns_lookup']:
    if hostname == fqdn.split('.')[0]:
      return '.'.join(fqdn.split('.')[1:])
  
  return None



def get_log_date(filepath):
  """Parses the year, month, and day from a beacon log filepath. This is 
  necessary because the timestamps within the beacon log don't include year.
  
  Parameters:
    filepath (str): The absolute path to a beacon log file
    
  Returns:
    str: The date of the beacon log in YYYY-MM-DD format
         Returns '' if no match is found
  """
  
  match = BEACON_FILEPATH_PATT.match(filepath)
  
  if match is not None:
    data = match.groupdict()
    
    return '-'.join([data['year'], data['month'], data['day']])
  
  return ''



def get_object_dict(obj_type, network, dns_domain):
  """Returns data of obj_type, filtered by network and dns_domain

  Parameters:
    obj_type (str):   A category of data (e.g., credentials, dns_info, GPOs)
    network (str):    A network identifer
    dns_domain (str): A DNS domain name

  Returns:
    dict: Filtered data of obj_type
  
  """
  if network in aggregator_vars[obj_type] and dns_domain in aggregator_vars[obj_type][network]:
    return aggregator_vars[obj_type][network][dns_domain]
  
  return None



#==============================================================================
#******                           Save / Load                            ******
#==============================================================================

def load_output_parsing_modules():
  """Loads custom output parsing modules."""
  global modules
  
  module_list = [os.path.splitext(mod)[0] for mod in os.listdir('modules') if mod.endswith('.py') and not mod.startswith('_')]

  for module_name in module_list:
    modules[module_name] = importlib.import_module('modules.' + module_name)



def load_json_file(job_name, filename, json_data):
  """Reads data from the specified JSON file or returns json_data if the file
  does not exist.
  
  Parameters:
    job_name (str):  The name of the current job
    filename (str):  The name of the JSON file to load
    json_data (obj): The object to return if the specified file does not exist
    
  Returns:
    obj: Either an object containing data read from the specified JSON file or
         json_data
  """
  
  filepath = os.path.join('jobs', job_name, filename)
  
  if os.path.exists(filepath):
    with open(filepath, 'r') as in_file:
      json_data = json.load(in_file)
  
  return json_data



def load_config(job_name):
  """Loads the configuration data for the specified job.
  
  Parameters:
    job_name (str): The name of the current job
    
  """
  if not os.path.exists('jobs/%s' % job_name):
    error('Job "%s" does not exist' % job_name)

  config = load_json_file(job_name, 'config.json', None)
  
  if config is None:
    error("%s is missing it's config.json" % job_name)
  else:
    config['job_name'] = job_name
  
  aggregator_vars['config'] = config



def load_state(job_name):
  """Loads job state from a previous run.
  
  Parameters:
    job_name: The name of the current job
  
  """
  global processed_files
  global aggregator_vars
  
  processed_files = load_json_file(job_name, 'processed_files.json', processed_files)
  aggregator_vars = load_json_file(job_name, 'saved_state.json', aggregator_vars)



def save_state(job_name):
  """Dumps the current job state to JSON files.
  
  Parameters:
    job_name: The name of the current job
    
  """
  job_dir = 'jobs/%s' % job_name
  
  with open(os.path.join(job_dir, 'processed_files.json'), 'w') as outfile:
    json.dump(processed_files, outfile)
  
  with open(os.path.join(job_dir, 'saved_state.json'), 'w') as outfile:
    json.dump(aggregator_vars, outfile)



#==============================================================================
#******                           User Prompts                           ******
#==============================================================================

def request_verify_directory(msg, default_dir):
  """Prompts the user until they specify a valid directory.
  
  Parameters:
    msg (str):          Prompt for user input
    default_dir (str):  The default directory to return if the user presses 
                        'Enter' without providing input
  
  Returns:
    str: The path to a valid directory
  """
  dir = None
  
  while dir is None:
    dir = raw_input(msg % default_dir)
    
    if dir == '':
      dir = default_dir
    
    if not os.path.exists(dir) or not os.path.isdir(dir):
      # NOTE: Don't need to log all the invalid directories a user tries, so just use print
      print('[-] ERROR: "%s" is not a valid directory' % dir)
      dir = None
  
  return dir



def request_missing_nt_domains():
  """Prompts the user to provide the associated NT domains for observed DNS
  domains which are not currently mapped in 'resources/domain_map.json'.
  
  """
  global domain_map
  
  domain_map = load_domains()
  
  if len(aggregator_vars['missing_domains']) > 0:
    log('[!] INPUT REQUIRED: The following DNS domains are not mapped to an NT domain. Please provide the associated NT domain for each DNS domain in order to continue.', suppress=False)
    
    for dns_domain in set(aggregator_vars['missing_domains']):
      nt_domain = raw_input('%s: ' % dns_domain).upper()
      domain_map[dns_domain] = nt_domain
      log('  - %s: %s' % (dns_domain, nt_domain))
      aggregator_vars['missing_domains'].remove(dns_domain)
    
    save_domains(domain_map)
    
    
def request_missing_dns_domain(nt_domain):
  """Prompts the user to provide the DNS domain associated with a given NT 
  domain.
  
  Parameters:
    nt_domain (str): The name of an NT domain
  
  Returns:
    str: The name of the associated DNS domain
  
  """
  global domain_map
  
  log('[!] INPUT REQUIRED: The following NT domain was detected but not mapped to a DNS domain. Please specify the associated DNS domain in order to continue.', suppress=False)
  
  dns_domain = raw_input('  %s: ' % nt_domain).upper()
  domain_map[dns_domain] = nt_domain
  save_domains(domain_map)
  
  return dns_domain



#==============================================================================
#******                            Utilities                             ******
#==============================================================================

def enhance_object(obj, network, dns_domain):
  """Performs various conversions and enhancements of Active Directory object 
  data.
    - Picks the more recent of lastLogon and lastLogonTimestamp, and converts 
      it to a human-readable timestamp
    - Converts pwdLastSet to a human-readable timestamp
    - Adds IP entries to computer objects, if DNS information is available
    - Adds credentials to users and computers, if the data is available
  
  Parameters:
    obj (dict):       A dictionary containing attributes of an Active 
                      Directory object
    network (str):    The network to which the object belongs
                      Used to find associated credentials, dns_info, and GPOs
    dns_domain (str): The DNS domain to which the object belongs
                      Used to find associated credentials, dns_info, and GPOs
  
  Returns:
    dict: An enhanced Active Directory object
    
  """
  creds = get_object_dict('credentials', network, dns_domain)
  dns_data = get_object_dict('dns_info', network, dns_domain)
  gpo_data = get_object_dict('gpos', network, dns_domain)
  
  GPO_NAME_PATT = re.compile('\{[0-9A-Fa-f\-]{36}\}')
  
  if 'trustpartner' in obj:
    obj['trustpartner'] = obj['trustpartner'].upper()
  
  if 'dnshostname' in obj.keys():
    obj['dnshostname'] = obj['dnshostname'].upper()
  
  # Attempt to derive name from various fields
  name = ''
  
  if 'samaccountname' in obj.keys():
    name = obj['samaccountname']
  elif 'name' in obj.keys():
    name = obj['name']
  elif 'dnshostname' in obj.keys():
    name = obj['dnshostname'].split('.')[0]
  
  if name == '':
    warn('Object contains no name field', obj)
    return None
  
  # If DNS data was provided, add the computer's IP
  if dns_data is not None:
    hostname = name.upper().rstrip('$')
    
    if hostname in dns_data and 'ip' in dns_data[hostname]:
      # Account for multiple IP addresses per host
      obj['ip'] = '\n'.join(set(dns_data[hostname]['ip']))
    else:
      # Set a default so CSV writer doesn't get angry if its 
      obj['ip'] = ''
  
  if 'realm' in obj:
    name = '\\'.join([obj['realm'], name])
  
  # Add credential fields
  if creds is not None:
    if name in creds:
      tmp_creds = creds[name]
      obj.update(tmp_creds)
    elif '$' not in name and name + '$' in creds:
      # Add credential fields for computer accounts
      tmp_creds = creds[name + '$']
      obj.update(tmp_creds)
  
  if 'lastlogon' in obj.keys() and 'lastlogontimestamp' in obj.keys():
    obj['lastlogon'] = max(obj['lastlogon'], obj['lastlogontimestamp'])
    del obj['lastlogontimestamp']
  elif 'lastlogontimestamp' in obj.keys():
    obj['lastlogon'] = obj['lastlogontimestamp']
    del obj['lastlogontimestamp']
  
  # Replace values in gplink with 
  if gpo_data is not None and 'gplink' in obj.keys():
    gpos = []
    gpo_names = GPO_NAME_PATT.findall(obj['gplink'])
    
    for name in gpo_names:
      if name in gpo_data:
        gpos.append(gpo_data[name]['displayname'])
      else:
        # All GPOs should be found, but just in case, it's good to know if data is missing
        gpos.append(name)
    
    obj['gpos'] = '\n'.join(gpos)
    del obj['gplink']
  
  return obj



def recategorize_cred(cred):
  """Attempts to determine the DNS domain for a credential based on its realm.
  
  Parameters:
    cred (dict):      The credential object
  
  Returns:
    str: The DNS domain to which the credential belongs
  
  """
  # Reverse map NT domains to DNS domains
  nt_domain_map = {}
  
  for dns_domain, nt_domain in domain_map.items():
    if nt_domain not in nt_domain_map:
      nt_domain_map[nt_domain] = dns_domain
    else:
      warn('Duplicate NT domains detected for %s and %s' % (nt_domain_map[nt_domain], dns_domain))
  
  # Found creds for an NT domain not mapped to a DNS domain; prompt the user
  if cred['realm'] not in nt_domain_map:
    pprint(cred)
    dns_domain = request_missing_dns_domain(cred['realm'])
  else:
    dns_domain = nt_domain_map[cred['realm']]
  
  return dns_domain



def move_cred(cred_id, cred, network, dns_domain):
  """Initializes a new DNS domain for credentials (if necessary) and merges
  the given credential into the destination domain container.
  
  Parameters:
    cred_id (str):    The realmified username associated with the credential
                      Format: "<realm>\\<username>"
    cred (dict):      The credential object
    network (str):    The network from which the credential was harvested
    dns_domain (str): The DNS domain where the credential should be moved
  
  """
  init_aggregator_dict(aggregator_vars['credentials'], {'network': network}, dns_domain)
  domain_dict = aggregator_vars['credentials'][network][dns_domain]
  
  if cred_id in domain_dict:
    # Merge existing creds from the destination container into 
    # the source (anything properly categorized should be newer
    # and more accurate)
    # TODO: Verify this merges correctly!!
    merge_cred(domain_dict[cred_id], cred)
  else:
    domain_dict[cred_id] = cred



def post_process_credentials():
  """Ensures all credentials have the correct realm and are properly
  categorized by DNS domain.
  
  """
  # This is...complex...good luck!
  
  for network, network_data in aggregator_vars['credentials'].items():
    if 'UNKNOWN' in network_data:
      # Find and correct the categorization of creds whose DNS domain was unknown at the time of collection
      for cred_id, cred in network_data['UNKNOWN'].items():
        host = aggregator_vars['hosts'][cred['collected_from']]
      
        if cred['type'] == 'local':
          if 'dns_domain' not in host:
            dns_domain = get_dns_domain_by_hostname(host['hostname'])
            
            if dns_domain is None:
              # DNS domain is still unknown; prompt the user
              host['dns_domain'] = raw_input('\n[!] INPUT REQUIRED:\n  Please specify the DNS domain for %s: ' % host['id']).upper()
            else:
              host['dns_domain'] = dns_domain
            
            # Make sure we have a matching NT domain; if not, prompt the user
            if host['dns_domain'] not in domain_map:
              aggregator_vars['missing_domains'].append(host['dns_domain'])
              request_missing_nt_domains()
          
          dns_domain = host['dns_domain']
          host['nt_domain'] = domain_map[dns_domain]
          
          # Determine if 'local' cred is actually a 'domain' cred; update as necessary
          if 'ldap' in host['services']:
            cred['type'] = 'domain'
            cred['realm'] = host['nt_domain']
        else:
          dns_domain = recategorize_cred(cred)
        
        move_cred(cred_id, cred, network, dns_domain)
        
        # Remove the old 'unknown' cred entry
        del network_data['UNKNOWN'][cred_id]
    
    
    for dns_domain, domain_data in network_data.items():
      # Skip any unknown creds as they have already been processed
      # There should be any by this point but might end up with undefined results if there are, better to just skip it
      if dns_domain == 'UNKNOWN':
        continue
    
      for cred_id, cred in domain_data.items():
        if cred['type'] == 'local':
          # Identify and update the type of any 'local' creds which are in fact 'domain' creds
          # NOTE: This is done during post-processing rather than at parsing time because the NT domain may not be known at parsing time
          host = get_host_by_name(cred['realm'])
          
          if 'ldap' in host['services']:
            cred['type'] = 'domain'
            cred['realm'] = domain_map[dns_domain]
        else:
          # Find domain creds that were attributed to the wrong domain
          if cred['realm'] != domain_map[dns_domain]:
            dns_domain = recategorize_cred(cred)
            move_cred(cred_id, cred, network, dns_domain)
        
            # Remove the old mis-attributed cred
            del network_data[dns_domain][cred_id]



#==============================================================================
#******                        Writing Functions                         ******
#==============================================================================

def write_commands():
  """Writes a CSV file containing a list of all the commands executed on 
  beacons within the scanned directory and associated host/session data.
  
  """
  config = aggregator_vars['config']
  
  # Appending timestamp would be nice, but it will create a new file; if we are skipping already parsed files, the commands will be split across multiple files
  outfile = os.path.join(config['command_output_directory'], '%s_beacon_commands_%s.csv' % (config['job_name'], DATESTAMP))
  
  log('[*] Writing command output to %s' % outfile, suppress=False)
  
  commands = []
  
  # Enrich and post-process command data before printing
  for command in aggregator_vars['commands']:
    # Make a copy of the command object because we have to delete the session_id in order to print it, but without the copy doing so will remove it from the original command object causing the job to fail on the next incremental run
    comm = dict(command)
    
    session_id = comm['session_id']
    del comm['session_id']
    
    session = aggregator_vars['sessions'][session_id]
    host = aggregator_vars['hosts'][session['host_id']]
    
    # Enrich command data with host and session info
    comm['ip'] = host['ip']
    comm['hostname'] = host['hostname']
    comm['os'] = host['os']
    comm['kernel'] = host['kernel']
    comm['host_arch'] = host['arch']
    
    comm['teamserver'] = session['teamserver']
    comm['beacon_id'] = session['beacon_id']
    comm['source'] = session['source']
    comm['direction'] = session['direction']
    comm['beacon_arch'] = session['beacon_arch']
    comm['pid'] = session['pid']
    
    # Post-process 'source' field to replace the beacon ID with a host identifier
    if 'beacon_' in comm['source']:
      # Beacon IDs are internal to the teamserver, so the teamserver IP should be the same between the command object and the source beacon ID
      src_sess_id = get_session_id(session['teamserver'], comm['source'])
      
      if src_sess_id in aggregator_vars['sessions']:
        src_session = aggregator_vars['sessions'][src_sess_id]
        src_host = aggregator_vars['hosts'][src_session['host_id']]
        comm['source'] = src_host['id']
      else:
        error('Unknown command source' % comm['source'], comm, fatal=False)
    
    commands.append(comm)
  
  write_success = False
  
  while not write_success:
    try:
      # NOTE: We could append, but all of the command data is stored in the job's state and this will result in duplicates unless we check times or if the entry is already in the file; it's simpler and possibly faster to just overwrite the file with all of the commands from the stored state
      with open(outfile, 'wb') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=FIELDNAMES['commands'])
        writer.writeheader()
        writer.writerows(commands)
      
      write_success = True
    except IOError as e:
      log(e)
      # Warn user, allow them to close the file, and try to save again, rather than lose all the data that was processed
      raw_input('[-] Write failed; do you have the file open?')



def write_all_credentials():
  """Exports a master list of all credentials in CSV and password cracker 
  ingest formats.
  
  """
  cred_list = []
  config = aggregator_vars['config']
  outfile = os.path.join(config['data_directory'], '%s_credentials_%s.csv' % (config['job_name'], DATESTAMP))
  write_success = False
  
  while not write_success:
    try:
      # NOTE: We could append, but all of the credential data is stored in the job's state and this will result in duplicates unless we check whether the entry is already in the file; it's simpler and possibly faster to just overwrite the file with all of the credentials from the stored state
      with open(outfile, 'wb') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=FIELDNAMES['credentials'])
        writer.writeheader()
        
        for network, network_data in aggregator_vars['credentials'].items():
          for dns_domain, domain_data in network_data.items():
            for cred_id, cred in domain_data.items():
              # Issue a unique number to each credential object
              if 'num' not in cred:
                cred['num'] = aggregator_vars['num_creds']
                aggregator_vars['num_creds'] += 1
              
              writer.writerow(cred)
              
              if 'ntlm' in cred:
                cred_list.append({'username': cred_id, 'ntlm': cred['ntlm']})
      
      write_success = True
    except IOError as e:
      log(e)
      # Warn user, allow them to close the file, and try to save again, rather than lose all the data that was processed
      raw_input('[-] Write failed; do you have the file open?')

  # Write usernames and NTLM hashes out to a text file that can be ingested into a password cracker
  if len(cred_list) > 0:
    write_success = False
  
    while not write_success:
      try:
        outfile = os.path.join(config['data_directory'], '%s_password_cracker_ingest.txt' % config['job_name'])
        
        with open(outfile, 'wb') as csvfile:
          writer = csv.DictWriter(csvfile, fieldnames=['username', 'ntlm'], delimiter=':')
          writer.writerows(cred_list)
          
        write_success = True
      except IOError as e:
        log(e)
        # Warn user, allow them to close the file, and try to save again, rather than lose all the data that was processed
        raw_input('[-] Write failed; do you have the file open?')



def write_domain_data():
  """Outputs CSV files of domain-related data such as dsquery output."""
  log('[*] Writing domain data...', suppress=False)
  
  for obj_type, object_data in aggregator_vars.items():
    # Skip non-domain data types
    if obj_type not in FIELDNAMES.keys():
      continue
    
    if type(object_data) is dict:
      log('    - %s' % obj_type)
      
      for network, network_data in object_data.items():
        for dns_domain, domain_data in network_data.items():
          tld = get_tld(dns_domain)
          nt_domain = domain_map[dns_domain] if dns_domain in domain_map else dns_domain
          
          # Appending timestamp is nice, but it will create a new file; if we are skipping already parsed files, the commands will be split across multiple files
          outfile = os.path.join(aggregator_vars['config']['data_directory'], 'network_data', network, tld, dns_domain, '%s_%s_%s.csv' % (nt_domain, obj_type, DATESTAMP))
          
          dir_name = os.path.dirname(outfile)
          
          # Create custom directories, if necessary
          if not os.path.exists(dir_name):
            os.makedirs(dir_name)
          
          write_success = False
          
          while not write_success:
            try:
              with open(outfile, 'wb') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=FIELDNAMES[obj_type])
                writer.writeheader()
                
                # Enrich and post-process object data before printing
                for key, data in domain_data.items():
                  if obj_type in ['computers', 'users', 'ous']:
                    data = enhance_object(data, network, dns_domain)
                    
                    if data is None:
                      continue
                
                  # Create a new object with only the fields to be printed
                  obj = {}
                  
                  for k, v in data.items():
                    if k in FIELDNAMES[obj_type]:
                      if type(v) is list:
                        obj[k] = '\n'.join(v)
                      elif k in ['pwdlastset', 'lastlogon']:
                        # NOTE: Store the timestamp in NT time and only convert when printing to avoid complications when doing incremental updates (i.e., if you store the printable time, you have to accomodate it in enhance_object())
                        obj[k] = convert_nt_time(v)
                      elif k == 'useraccountcontrol':
                        obj[k] = convert_uac(v)
                      else:
                        obj[k] = v
                  
                  # Don't print the object if it's empty (except for ADsPath); this indicates an object type mismatch
                  if len(obj) > 1:
                    writer.writerow(obj)
              
              write_success = True
            except IOError as e:
              log(e)
              # Warn user, allow them to close the file, and try to save again, rather than lose all the data that was processed
              raw_input('[-] Write failed; do you have the file open?')



def write_host_data():
  """Outputs custom data associated with a specific host.
  
  Output parsing modules may extend the default host schema with dictionaries
  of the format: 
    {'fieldnames': ['', ...], 'data': [{}, ..]}
  This function will generate CSV files using the fieldnames and data provided
  in the custom dictionary.
  
  Additionally, this function will print raw text files for any values stored
  in the 'text' attribute which must have the format: 
    {'filepath': '...', 'data': '...'}
  The filepath should be relative to the host output directory; additional 
  directories will be automatically created as necessary.
  """
  log('[*] Writing host data...', suppress=False)
  
  for host_id, host in aggregator_vars['hosts'].items():
    # Construct output filepath
    output_dir = os.path.join(aggregator_vars['config']['data_directory'], 'network_data')
    
    if 'network' in host.keys():
      output_dir = os.path.join(output_dir, host['network'])
    else:
      output_dir = os.path.join(output_dir, 'UNKNOWN')
  
    if 'dns_domain' in host.keys():
      dns_domain = host['dns_domain']
      tld = get_tld(dns_domain)
      output_dir = os.path.join(output_dir, tld, dns_domain)
    else:
      output_dir = os.path.join(output_dir, 'UNKNOWN', 'UNKNOWN')
    
    output_dir = os.path.join(output_dir, 'hosts', host_id)
    
    # Create host directory, if necessary
    if not os.path.exists(output_dir) or not os.path.isdir(output_dir):
      os.makedirs(output_dir)
    
    log('   - %s\n       %s' % (host['id'], output_dir))
    
    # Create CSV files for custom data added by output parsing modules
    for attrib, data in host.items():
      # Look for any custom dictionary that contains a 'fieldnames' key; this will ignore 'text' which is handled separately below
      if type(data) == dict and 'fieldnames' in data.keys():
        # Create directory for custom data type, if necessary
        attrib_dir = os.path.join(output_dir, attrib)
        
        if not os.path.exists(attrib_dir):
          os.makedirs(attrib_dir)
        
        for tstamp, instance in data['data'].items():
          tstamp = dt.strptime(tstamp, TIMEFORMAT_LOG).strftime(TIMEFORMAT_FILE)
          outfile = os.path.join(attrib_dir, '%s_%s_%s.csv' % (host['hostname'], tstamp, attrib))
          write_success = False
          
          while not write_success:
            try:
              with open(outfile, 'wb') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=data['fieldnames'])
                writer.writeheader()
                writer.writerows(instance)
                write_success = True
            except IOError as e:
              log(e)
              # Warn user, allow them to close the file, and try to save again, rather than lose all the data that was processed
              raw_input('[-] Write failed; do you have the file open?')
    
    # Write raw text files extracted by output parsing modules
    for filepath, data in host['text'].items():
      abs_path = os.path.join(output_dir, filepath)
      dir_name = os.path.dirname(abs_path)
      
      # Create custom directories, if necessary
      if not os.path.exists(dir_name):
        os.makedirs(dir_name)
      
      write_success = False
      
      while not write_success:
        try:
          with open(abs_path, 'w') as out_file:
            out_file.writelines(data)
          
          write_success = True
        except IOError as e:
          log(e)
          # Warn user, allow them to close the file, and try to save again, rather than lose all the data that was processed
          # Doubt this will ever happen with flat text files, but why risk it?
          raw_input('[-] Write failed; do you have the file open?')



#==============================================================================
#******                          Beacon Parsing                          ******
#==============================================================================

def parse_session_metadata(filepath):
  """Parses information about the host and session from the first line of the 
  beacon log (if it exists) and updates the global hosts and sessions 
  dictionaries.
    
  Parameters:
    filepath (str): The absolute path to a beacon log file

  Returns:
    str: The session identifer associated with the given beacon log
  
  """
  global aggregator_vars
  
  # Parse teamserver IP and beacon ID from the filepath
  # IMPORTANT: Relies on logs being stored in the proper directory structure
  beacon_metadata = BEACON_FILEPATH_PATT.search(filepath)
  network = 'unknown'
  
  if beacon_metadata is not None:
    beacon_metadata = beacon_metadata.groupdict()
    teamserver_ip = beacon_metadata['teamserver']
    beacon_id = beacon_metadata['beacon_id']
    network = beacon_metadata['network']
  else:
    error('Invalid directory structure detected; unable to determine teamserver IP')
  
  # NOTE: Use a combination of teamserver and beacon ID to uniquely indentify the session; addition of teamserver IP prevents collisions if two teamservers happen to generate the same beacon ID
  session_id = get_session_id(teamserver_ip, beacon_id)
  
  with open(filepath, 'r') as beacon_log:
    line = beacon_log.readline()
    
    beacon_metadata = SESSION_INFO_PATT.search(line)
    
    if beacon_metadata is not None:
      # First line of the log contains session metadata
      beacon_metadata = beacon_metadata.groupdict()
      beacon_metadata['hostname'] = beacon_metadata['hostname'].upper()
      
      host_id = '%s (%s)' % (beacon_metadata['ip'], beacon_metadata['hostname'])
      
      host = {}
      host['id'] = host_id
      host['network'] = network
      host['ip'] = beacon_metadata['ip']
      host['hostname'] = beacon_metadata['hostname']
      host['os'] = beacon_metadata['os']
      host['kernel'] = beacon_metadata['kernel']
      host['arch'] = beacon_metadata['host_arch']
      host['services'] = []
      host['text'] = {}
      
      # Correct IP for local connection
      if host['ip'] == '127.0.0.1' and host['hostname'] in aggregator_vars['dns_lookup']:
        host['ip'] = aggregator_vars['dns_lookup'][host['hostname']]
      else:
        # Store IP in dns_lookup for future corrections
        aggregator_vars['dns_lookup'][host['hostname']] = host['ip']
      
      if not host_id in aggregator_vars['hosts']:
        aggregator_vars['hosts'][host_id] = host
      
      session = {}
      session['teamserver'] = teamserver_ip
      session['source'] = beacon_metadata['source']
      session['direction'] = beacon_metadata['direction']
      session['host_id'] = host_id
      session['pid'] = beacon_metadata['pid']
      session['beacon_arch'] = beacon_metadata['beacon_arch']
      session['user'] = beacon_metadata['user']
      session['beacon_id'] = beacon_id
      session['filepath'] = filepath
      
      
      if not session_id in aggregator_vars['sessions']:
        aggregator_vars['sessions'][session_id] = session
      else:
        # It's possible to get multiple beacon logs with identical session data (e.g., if you connect to the same SMB (or probably TCP) session)
        # Error on any sessions that have the same session ID but are different
        # NOTE: Create copies because you have to eliminate the filepath for an accurate comparison
        existing_session = dict(aggregator_vars['sessions'][session_id])
        del existing_session['filepath']
        
        current_session = dict(session)
        del current_session['filepath']
        
        if current_session != existing_session:
          debug('Saved Session', aggregator_vars['sessions'][session_id])
          debug('Current Session:', session)
          error('[*] Unique sessions detected with the same ID (%s)' % session_id)
    elif session_id in aggregator_vars['sessions']:
      # First line does NOT contain session metadata, but the session data can be determined based on the teamserver IP and beacon ID (which form the session_id)
      session = aggregator_vars['sessions'][session_id]
    else:
      # Beacon log does not contain session metadata and a matching session could not be found in the session list
      warn('Session from unknown host (%s)' % filepath)
      debug('', aggregator_vars['sessions'])
      return None
  
  return session_id



# TODO:
#   Test that if getting BIG output, multiple checkins don't get logged and break up the output
#   Test that the output from each command is in it's own [output] section and not broken up between multiple outpute sections
def parse_output_blob(tstamp, output, session_id):
  """Iterates through every line of the given beacon log file and parse/record
  information about each input command.
  
  Parameters:
    tstamp (str):     The timestamp when the command output was received
                      (format 'YYYY-MM-DD HH:mm:ss')
    output (text):    The output text from a command
    session_id (str): The session identifer associated with the given beacon
                      log, as generated by parse_session_metadata()
  
  """
  global aggregator_vars
  
  # NOTE: Pass the dictionary of aggregator variables to each module by 
  # reference; the matching module will directly update the dictionary. This 
  # allows individual modules to make conditional updates based on the 
  # existing data and eliminates the need to re-assign returned data to 
  # aggregator_vars. Passing the data as a dictionary rather than as 
  # individual variables allows the addition of new aggregator variables 
  # without changing the function definitions of existing modules
  
  # Clean the data
  output = output.replace('received output:\n', '')
  
  host = get_host_by_session_id(session_id)
  
  try:
    debug('====================\n%s\n%s--------------------\n%s\n' % (aggregator_vars['sessions'][session_id]['filepath'], host['id'], output))
  except UnicodeDecodeError as e:
    warn(e)
  
  for mod_name, module in modules.items():
    # Pass data to each module; the module will determine whether the output matches the expected format, returning 'None' if it does not (i.e., automatic format recognition is left up to the module)
    match = module.parse_output(host, tstamp, output, aggregator_vars)
      
    # Update global aggregator variables
    if match:
      debug('--------------------\nOutput Type: %s\n====================\n' % mod_name)
    
      # NOTE: Output should only match one module; to increase performance, don't bother checking others once one is found
      break



def parse_beacon_commands(filepath, date, session_id):
  """Iterates through every line of the beacon log data and parses/records 
  information about each command run.
    
  Parameters:
    filepath (str):   The absolute path to a beacon log file
    date (str):       The date of the becaon log (format: YYYY-MM-DD)
    session_id (str): The session identifer associated with the given beacon
                      log, as generated by parse_session_metadata()
  
  """
  global aggregator_vars
  
  # Read log data in line-by-line so we can keep track of the state of the session (e.g., whether credentials are applied when commands are run)
  # NOTE: *sigh* Some Windows commands randomly use carriage returns with no line feeds which throws off the line number count; do gymnastics to clean up the data
  # Specifically, have to use 'rb' mode so Python won't strip the \r characters, then replace both EOL markers with a consistent \n and split on \n to get a list of lines
  with open(filepath, 'rb') as beacon_log:
    log_data = beacon_log.read().replace('\r\n', '\n').replace('\r', '\n').split('\n')
  
  creds = ''
  
  for i in xrange(0, len(log_data)):
    line = log_data[i]
    
    comm_data = INPUT_PATT.search(line)
    
    if comm_data is not None:
      comm_data = comm_data.groupdict()
      # NOTE: Get the date from the filepath (because the timestamp doesn't include year) and the time from the input line
      # Format: 'YYYY-MM-DD HH:mm:ss' (Excel will auto recognize this as a date and allow easier filtering)
      comm_data['timestamp'] = date + ' ' + comm_data['time']
      comm_data['user'] = aggregator_vars['sessions'][session_id]['user']
      comm_data['session_id'] = session_id
      # NOTE: Add 1 to account for Python starting at index 0 and text editors starting at line number 1
      comm_data['line_number'] = i + 1
      comm_data['filepath'] = filepath
      comm = comm_data['command'].strip()
      # NOTE: Time was integrated into the timestamp field and is no longer needed as a standalone field
      del comm_data['time']
      
      # User pressed Enter, didn't run command, ignore it
      if comm == '':
        continue
      
      # Update creds
      if 'make_token' in comm and len(comm.split(' ')) > 1:
        # NOTE: Impossible to automatically determine whether make_token creds are bad; since it's a network logon, it will always make the token, but the user won't know if it's valid or not until they try to use it
        creds = comm.split(' ')[1]
      elif 'steal_token' in comm:
        # Look ahead for 'Impersonated [domain]\[username]'; check for failures and don't try to read past the end of the file
        j = i + 1
        while (j < len(log_data)):
          if 'Impersonated' in log_data[j]:
            creds = log_data[j].split(' ')[1].strip()
            break
          
          # If rev2self, make_token, or steal_token is seen before the "Impersonated" line, the steal_token failed
          if 'rev2self' in log_data[j] or 'steal_token' in log_data[j] or 'make_token' in log_data[j]:
            break
            
          j += 1
      elif 'rev2self' in comm:
        creds = ''
      
      # Update stored user credentials
      if creds != '':
        comm_data['user'] = '%s (%s)' % (comm_data['user'], creds)
      
      aggregator_vars['commands'].append(comm_data)



def parse_beacon_log(filepath):
  """Calls functions to parse the session metadata, input commands, and 
  command output.
    
  Parameters:
    filepath (str): The absolute path to a beacon log file
  
  """
  global processed_files
  
  log('[*] Parsing: %s' % filepath)
  
  session_id = parse_session_metadata(filepath)
  
  if session_id is not None:
    date = get_log_date(filepath)
    
    parse_beacon_commands(filepath, date, session_id)
    
    with open(filepath, 'r') as beacon_log:
      raw_data = beacon_log.read()
    
    # Find all blobs of output data and associated timestamps
    for output in OUTPUT_PATT.findall(raw_data):
      # 'output' is a tuple of timestamp and the blob of output data
    
      # NOTE: Get the date from the filepath (because the timestamp doesn't include year) and the time from the output line
      tstamp = date + ' ' + output[0]
      
      # NOTE: tstamp format is: 'YYYY-MM-DD HH:mm:ss' (easier to remove ':' and ' ' to make filename compatible than add them in the right places to make Excel compatible times)
      parse_output_blob(tstamp, output[1], session_id)
    
    # Record that the file has been processed
    processed_files.append(filepath)



def process_input_dir():
  """Walks the input_directory specified in the config, finds unprocessed 
  beacon log files and calls the parsing function on them.
  
  """
  config = aggregator_vars['config']
  
  for root, dirs, files in os.walk(config['command_output_directory']):
    for f in files:
      abs_path = os.path.join(root, f)
      
      # Only process beacon logs, and only files that haven't been previously parsed
      if 'beacon_' in f and f.endswith('.log'):
        if abs_path not in processed_files:
          parse_beacon_log(abs_path)
        else:
          log('[*] INFO: Skipping duplicate file (%s)' % abs_path)



#==============================================================================
#******                          Job Management                          ******
#==============================================================================

def create_job(job_name):
  """Creates a new job using user-provided input.
  
  Prompts user for necessary input, generates a new directory under jobs/, and
  creates a config.json file in the new jobs/<job_name> directory.
  
  Parameters:
    job_name (str): The name of the job to be created
  
  """
  job_dir = 'jobs/%s' % job_name
  
  if os.path.exists(job_dir):
    error('Job "%s" already exists' % job_name)
  
  config = {}
  default_log_dir = 'L:\\%s' % job_name
  default_data_dir = 'X:\\'
  
  config['input_directory'] = request_verify_directory('Directory to scan [%s]: ', default_log_dir)
  config['command_output_directory'] = request_verify_directory('Beacon command output directory [%s]: ', default_log_dir)
  config['data_directory'] = request_verify_directory('Network data output directory [%s]: ', default_data_dir)
  
  dir_all = raw_input('Record all directory queries (default is recursive only) [y|N]: ').lower()
  config['dir_all'] = (dir_all == 'y' or dir_all == 'yes')
  
  # NOTE: Don't make the directory until the end in case the user bails
  os.makedirs(job_dir)
  
  with open(os.path.join(job_dir, 'config.json'), 'w') as outfile:
    json.dump(config, outfile)
  
  log('[+] New job "%s" created!' % job_name, suppress=False)
  
  show_job(job_name)



def list_jobs():
  """Displays a list of available jobs."""
  print('\nJOBS:')

  if len(os.listdir('jobs')) == 0:
    print('  There are no jobs loaded\n')
  else:
    for job in os.listdir('jobs'):
      print('  ' + job)
    
    print('')



def show_job(job_name):
  """Displays the configuration of the specified job.
  
  Parameters:
    job_name (str): The name of the job whose configuration should be 
                    displayed
  
  """
  load_config(job_name)
  config = aggregator_vars['config']
  
  print('')
  log('%s Config:' % job_name, suppress=False)
  
  for key in config.keys():
    name = key.replace('_', ' ').title()
    log('  %s: %s' % (name, config[key]), suppress=False)
  
  print('')



def run_job(job_name, force_reset=False):
  """Executes the specified job, optionally ignoring previous state data.
  
  Parameters:
    job_name (str):     The name of the job to be executed
    force_reset (bool): Whether or not previous state data should be ignored
                        Optional; default (False)
  
  """
  log('[+] Running %s' % job_name, suppress=False)
  
  
  # If force_reset, ignore previous state; all files will be parsed and current state will be overwritten
  if not force_reset:
    load_state(job_name)
  
  # Load configuration after load_state() so it's not overwritten
  load_config(job_name)
  
  # Record start time
  start_time = dt.now()
  log('[+] Start Time: %s' % start_time.strftime(TIMEFORMAT_LOG), suppress=False)
  
  load_output_parsing_modules()
  process_input_dir()
  # Save temporary state in case the user bails while being prompted for missing data
  save_state(job_name)
  
  log('[+] Finished parsing data', suppress=False)
  log('[*] Time Elapsed: %s' % str(dt.now() - start_time), suppress=False)
  
  request_missing_nt_domains()
  post_process_credentials()
  
  log('[+] Post-processing complete', suppress=False)
  log('[*] Time Elapsed: %s' % str(dt.now() - start_time), suppress=False)
  
  write_commands()
  # NOTE: Call write_all_credentials() before printing host and domain data because write_all_credentials() generates the unique ID numbers for each credential object
  write_all_credentials()
  write_domain_data()
  write_host_data()
  
  # Save final processed state
  save_state(job_name)
  
  # Record end time
  end_time = dt.now()
  print('')
  log('[+] End Time: %s' % end_time.strftime(TIMEFORMAT_LOG), suppress=False)
  print('')
  log('[+] Time Elapsed: %s' % str(dt.now() - start_time), suppress=False)
  print('')



def delete_job(job_name):
  """Deletes the specified job.
  
  Parameters:
    job_name (str): The name of the job to be deleted
  
  """
  if not os.path.exists('jobs/%s' % job_name):
    error('Job "%s" does not exist' % job_name)
  
  confirm = raw_input('Are you sure you want to delete %s [y|N]: ' % job_name)
  
  if confirm.lower() == 'y' or confirm.lower() == 'yes':
    shutil.rmtree('jobs/%s' % job_name)



def main():
  parser = OptionParser()
  parser.add_option("-a", "--all", dest="all_jobs", action="store_true", help="Run all jobs")
  parser.add_option("-c", "--create", dest="new_job", help="Name of new job to create")
  parser.add_option("-d", "--delete", dest="delete_job", help="Name of job to delete")
  parser.add_option("-f", "--force", dest="force", action="store_true", help="Force the script to parse all of the data from scratch (WARNING: This will overwrite all stored data)")
  parser.add_option("-l", "--list", dest="list_jobs", action="store_true", help="List jobs")
  parser.add_option("-r", "--run", dest="run_job", help="Name of job to run (must already exist)")
  parser.add_option("-s", "--show", dest="show_job", help="Show the config for a specified job")
  parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="Indicates verbose output (i.e., progress should be printed to the screen")
  (options, args) = parser.parse_args()
  
  if options.verbose:
    set_verbose()
  
  print(BANNER)
  
  # Print help if no options are specified
  if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(0)
  
  if options.list_jobs:
    list_jobs()
  
  if options.all_jobs:
    for job_name in os.listdir('jobs'):
      run_job(job_name, options.force)
  
  if options.new_job is not None:
    create_job(options.new_job)
    
    run_now = raw_input('Run job immediately [Y|n]: ')
    
    if run_now != 'n':
      options.run_job = options.new_job
      print('')
      
  if options.show_job is not None:
    show_job(options.show_job)
  
  if options.run_job is not None:
    run_job(options.run_job, options.force)
  
  if options.delete_job is not None:
    delete_job(options.delete_job)



if __name__ == "__main__":
  main()