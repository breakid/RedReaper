import re
from pprint import pprint


# Example: " Directory of C:\Users"
ROOT_DIR_PATT = re.compile(' Directory of (?P<dir>.*)')

# Example: "04/15/2019  00:58 AM"
DATETIME_PATT = '(?P<month>\d{2})/(?P<day>\d{2})/(?P<year>\d{4})  (?P<hour>\d{2}):(?P<minute>\d{2}) (?P<period>[AP]M)'

# Example: "04/18/2019  23:02 PM    <DIR>          logs"
DIR_PATT = re.compile(DATETIME_PATT + '    <DIR>[ ]*(?P<entry>.*)')

# Example: "04/18/2019  23:30 PM            11,256 README.txt"
FILE_PATT = re.compile(DATETIME_PATT + '[ ]*(?P<size>[\d\,]*) (?P<entry>.*)')

# Example: "               2 File(s)         57,114 bytes"
DIR_SIZE_PATT = re.compile('.*?(?P<size>[\d\,]*) bytes')


def parse_output(host, tstamp, output, global_vars):
  """Parses dir output.
  
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
  
  if output.startswith(' Volume in drive '):
    rows = []
    root_dir = ''
    
    # Stores the sizes of directories, to be added during post-processing
    dir_size_map = {}
    
    # Used to determine whether or not the dir is recursive 
    num_root_dirs = 0
    
    for line in output.split('\n'):
      row = {}
      data = None
      
      # Determine which (if any) pattern the current line matches
      match = DIR_PATT.match(line)
      
      if match is not None:
        data = match.groupdict()
        data['type'] = 'dir'
      else:
        match = FILE_PATT.match(line)
        
        if match is not None:
          data = match.groupdict()
          data['type'] = 'file'
        else:
          match = ROOT_DIR_PATT.match(line)
          
          if match is not None:
            root_dir = match.groupdict()['dir']
            num_root_dirs += 1
            
            if not root_dir.endswith('\\'):
              root_dir += '\\'
          else:
            match = DIR_SIZE_PATT.match(line)
            
            # Record the size of the directory so it can be add during post-processing
            if match is not None and root_dir not in dir_size_map:
              dir_size_map[root_dir] = match.groupdict()['size']
      
      # Parse data from directory or file entries
      if data is not None:
        # Skip reference to current and parent directories
        if data['entry'] in ['.', '..']:
          continue
      
        row['date'] = '{0}-{1}-{2} {3}:{4}'.format(data['year'], data['month'], data['day'], data['hour'], data['minute'])
        row['type'] = data['type']
        row['size'] = data['size'] if 'size' in data else 'Unknown' #'Access Denied'
        row['entry'] = root_dir + data['entry']
        rows.append(row)
    
    for row in rows:
      # Post-process directory sizes into applicable entries
      if row['size'] == 'Unknown':
        entry = row['entry'] + '\\'
        
        if entry in dir_size_map:
          row['size'] = dir_size_map[entry]
    
    # Only record the directory if it has more than one root_dir (i.e., it's a recursive dir) or 'dir_all' is set in the config
    if num_root_dirs > 1 or ('dir_all' in global_vars['config'] and global_vars['config']['dir_all']):
      if 'dir' not in host.keys():
        host['dir'] = {}
        host['dir']['fieldnames'] = ['date', 'type', 'size', 'entry']
        host['dir']['data'] = {}
      
      if len(rows) > 0:
        host['dir']['data'][tstamp] = rows
    
    return True
  
  return False
