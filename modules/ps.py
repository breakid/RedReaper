import csv
import os
import re
from pprint import pprint
from _utils import *

# Output from a process that could not be enumerated with the current credentials
# Example: "System	0	4"
PROTECTED_PROC_PATT = re.compile('(?P<process_name>.*?)\t(?P<ppid>\d+)\t(?P<pid>\d+)\n')

# Output from a fully enumerated process
# Example: "powershell.exe	4132	4248	x86	SGC\sam.carter	2"
PROC_PATT = re.compile('(?P<process_name>.*?)\t(?P<ppid>\d+)\t(?P<pid>\d+)\t(?P<arch>x\d{2})\t(?P<owner>.*?)\t(?P<session_id>\d+)')


# Load process name / description mapping from resource file
lookup_table = {}
lookup_table_file = 'resources\\process_lookup_table.txt'

if os.path.exists(lookup_table_file):
  with open(lookup_table_file, 'r') as in_file:
    data = csv.reader(in_file, delimiter='|')
    
    for row in data:
      lookup_table[row[0].lower()] = {
        'category': row[1],
        'desc': row[2]
      }


def parse_output(host, tstamp, output, global_vars):
  """Parses ps output to store process lists associated with the given host.
  
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
  
  if output.startswith('[System Process]\t0\t0'):
    processes = []
    missing_procs = []
    
    proc1 = [p.groupdict() for p in PROTECTED_PROC_PATT.finditer(output)]
    proc2 = [p.groupdict() for p in PROC_PATT.finditer(output)]
    
    for proc in (proc1 + proc2):
      name = proc['process_name'].lower()

      if name in lookup_table:
        proc.update(lookup_table[name])
      else:
        missing_procs.append(name)
      
      processes.append(proc)
    
    # Record the names of processes that weren't found in 'resources\\process_lookup_table.txt', so they can easily be researched and added
    with open('logs\\missing_procs.txt', 'a') as outfile:
      outfile.writelines('\n'.join(missing_procs) + '\n')
    
    if 'ps' not in host.keys():
      host['ps'] = {}
      if len(lookup_table) > 0:
        host['ps']['fieldnames'] = ['category', 'ppid', 'pid', 'arch', 'process_name', 'owner', 'session_id', 'desc']
      else:
        host['ps']['fieldnames'] = ['process_name', 'ppid', 'pid', 'arch', 'owner', 'session_id']
      host['ps']['data'] = {}
    
    host['ps']['data'][tstamp] = processes
    
    return True
    
  return False
