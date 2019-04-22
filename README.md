
<pre>
  ===========================================================
  ______ ___________  ______ _____  ___  ______ ___________ 
  | ___ \  ___|  _  \ | ___ \  ___|/ _ \ | ___ \  ___| ___ \
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
                                                      
</pre>

----

### Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Assumptions](#assumptions)
5. [Limitations](#limitations)
6. [Usage](#usage)

----

### [OVERVIEW](#overview)
- This tool is designed to simplify and automate the extraction and organization of useful data from Cobalt Strike logs. Users must first create a new job, where they will be prompted for some basic configuration information such as the log directory to scan and where output data should be written. Running a job will cause the script to:

  1. Generate a list of all commands run, including the time the command was tasked, the user who performed the tasking, and information regarding the session in which the command was executed
      - The associated output is NOT available at this time due to how Cobalt Strike records its logs, but I hope to add this in the future
      
  2. Identify chunks of command output and pass these chunks to output parsing modules. Current modules support parsing:
      - ipconfig
      - ps
      - netstat
      - dir (defaults to recursive only but can specify 'all' in the config)
      - dsquery (complex commands in list format)
      - dnscmd (zoneprints)
      - hashdump
      - lsadump
      - logonpasswords
      - dcsync
      
  3. Dump parsed data to a hierarchical directory structure. Where possible, dsquery data will be enriched using other available data such as credentials or DNS information. Processed domain-specific data will be stored in the root of the domain directory, while raw text files will be extracted and written to appropriate sub-directories. Host-specific data such as process lists and netstats will be stored in host directories beneath their associated domain.

----

### [FEATURES](#features)
- Incremental updates
  - The script will keep track of which files it has already processed and save its current state to disc between executions. This allows the script to pick up where it left off without having to re-process old data. Only processing new files makes subsequent runs much faster.

- Modular output parsing
  - The usage of a modular output parsing framework means that support for new output types can easily be added without changing the main script.
  
- Auto-detection of output types
  - Output modules will automatically detect the type of output and parse it appropriately. This eliminates the need for a user to manually specify the type of output to parse as with [Parseltongue](https://github.com/breakid/parseltongue).
  - **Warning**: Anomalies may occur if the script receives data that is similar to but slightly different than the data for which it has been calibrated. See [Requirements](#requirements) and [Assumptions](#assumptions) for more details.

- Data enrichment
  - Process lists are annotated with the software product to which each process belongs (assuming the matching source data has been included in `resources\process_lookup_table.txt`. This improves the ability of users to quickly triage a list of processes.
  - Net connections are annotated with their associated processes and process descriptions, provided: the PID is included in the `netstat` output (`-o`), a `ps` was run **BEFORE** the `netstat`, and the process information is included in `resources\process_lookup_table.txt`.
  - User data from dsquery is enriched with credentials, if available.
  - Computer data from dsquery is enriched with credentials and DNS information, if available.

- Raw file export
  - While effort was taken to parse as much useful data as possible from output, some data does not lend itself well to this such as the hash history provided by DCsync. When these files are encountered, the script will automatically export the raw output to an appropriate directory.

- Automatic data organization in a hierarchical directory structure
  - The script will automatically generate and populate a hierarchical directory structure to intuitively organize extracted data. This relies on knowledge of the host's DNS domain as obtained from `ipconfig`. See [Limitations](#limitations) for more details.

- Service / function detection
  - Rudimentary service detection is implemented by parsing listening ports from a `netstat`. Services can be used to determine the function of some hosts. Specifically, identifying a host as a Domain Controller allows password hashes dumped from this host to be associated with the NT domain rather than the host itself.

- Lists credentialed applied to Beacon sessions
  - The script will specify when credentials are applied to a session via `make_token` or `steal_token`. Some limitations apply, see [Limitations](#limitations) for more details.

- All username / NTLM hash pairs are dumped to a file for easy ingestion into a password cracker.

- Numbered credentials
  - Credentials include a `comment` column, but subsequent executions may add credentials and users need a way to reliably transfer comments. A number column was added that allows users to sort both the old and new credential files the same so the comments can be copied from one to the other. New credentials will always be added to the end of the list (when ordered by this number) so they will not throw off the comment order for older credentials.

- Graceful handling of locked files
  - Excel will lock CSV files. This prevents the script from writing to a file when someone has it open. To avoid having to completely re-process all of the data, the script will simply prompt the user to close the file and resume trying to write rather than bailing.

- Logging
  - The script's progress and any error messages are written to a log file for easy review.

----

### [REQUIREMENTS](#requirements)
- Python 2.7

- Beacon logs must be stored in the following directory structure
  > `...\<engagement_name>\<network>\<year>\<month>\<day>\...\<teamserver_id (IP, domain name, etc.)>\<host_ip>\<beacon_id>.log`
  
  - This format is necessary to extract the **year** for accurate date/timestamps and the **teamserver identifier** which is used in the beacon command output file and in combination with the beacon ID to uniquely identify each session
  - Other aspects of the path can be changed, but the regex will have to be updated

- Entries should be created in `resources\domain_map.json` mapping each DNS domain to it's NT domain
  - This is required to name domain-specific files (e.g., dsqueries, credentials, etc.) properly and apply the NT domain to domain credentials
  - If the script detects a DNS domain that is not in this file, the user will be prompted to input the associated NT domain. This data will be saved to `resources\domain_map.json` for future reference.

- An `ipconfig` **MUST** be run on each new host
  - The `ipconfig` is used to determine the host's DNS domain (and indirectly the NT domain)
  - If `ipconfig` is not run, the script will attempt various other ways of obtaining the DNS domain, but `ipconfig` is the most reliable.
  
- Always include `ADsPath` and output in list format if you want the dsquery to be parsed
  - The `ADsPath` is used to determine the domain to which objects belong

- The `resources\process_lookup_table.txt` file must be updated periodically to allow for accurate enrichment of process lists
  - This file uses the same format as processcolor, and therefore the same file can be used
  - A `missing_procs.txt` file is generated in the log directory to make it easy to identify new processes to research (will likely contain duplicates)

----

### [ASSUMPTIONS](#assumptions)
- RedReaper is executed from Windows, and Cobalt Strike log files are stored on a Windows-compatible filesystem (e.g., local Windows drive, Windows fileshare, SAMBA share, etc.). RedReaper should run on Linux with little to no modification, but it has not been tested under these conditions.

- RedReaper will only be run against completed log files. The job management feature keeps track of processed files and will not automatically re-process them. Therefore, if additional information is added to the log file it will not be parsed. If you want to parse active logs, you will need to use the `-f` option. RedReaper has not been tested under these conditions, so you may experience unexpected results.
  - Recommended usage is to run once per day. This could be done manually at the conclusion of daily activities or at midnight via a scheduled task / cron job.

- All output will only match a single output parsing module. As such, once a match is found, the script will move on to the next section of output.

- dsquery
    - Attribute order follows native dsquery order (i.e., each object ends with `ADsPath`)
      - `ADsPath` is used as a delimiter between objects

    - All objects in a single query are of the same type and from the same domain
      - The type of the last object is used to categorize the entire query
      - The domain component of the last object's `ADsPath` is used to determine the DNS domain for the entire query
    
    - The following attributes will be unique to the associated object type (i.e., used for automatic type detection):
      - `DisplayName` &rarr; GroupPolicyContainer
      - `GPLink` &rarr; OrganizationalUnit
      - `OperatingSystem` &rarr; Computer
      - `PwdLastSe`t &rarr; User
      - `Flatname` &rarr; Trust

- Raw beacon logs will be viewed in a Windows text editor such as Notepad++.
    - Some Windows commands print carriage returns (`\r`) without line feeds (`\n`). RedReaper corrects for this so that the line numbers in the `beacon_commands` file are accurate on Windows (tested in Notepad++); however, Linux interprets EOL conventions differently so the line numbers may be slightly off.

----

### [LIMITATIONS](#limitations)
- There is (currently) no way to automatically and reliably map DNS domain to NT domain; therefore this information must be manually provided in a resource file.

- If `ipconfig` is not run, the script will be unable to determine the host's DNS domain and will export its data to an `UNKNOWN` directory.

- There is no way to determine the validity of credentials from a `make_token`. Since it's a network logon, Cobalt Strike will always report that the token was applied; however, the token may or may not work when used.

----

### [USAGE](#usage)
- Run without any commands to show the help menu

- Create a job
  - `python RedReaper.py -c <job_name>`
    - User will be prompted for necessary data
    - To cancel before reaching the end of the wizard, press `CTRL + C`
    - When configuration is complete, the final configuration will be printed to the screen and the user will be prompted whether they want to run the job immediately

- List jobs
  - `python RedReaper.py -l`
    - Lists available jobs to run or delete

- Show a job's configuration
  - `python RedReaper.py -s <job_name>`
    - Prints the job's configuration
    - Alternatively, users can read or edit the JSON file stored in `jobs\<job_name>\config.json`

- Run a job
  - `python RedReaper.py -r <job_name> [-f]`
    - Executes a job
    - Optional `-f` argument forces the script to ignore the current state and re-process the entire job from scratch
      - WARNING: Files from a previous run will be overwritten. If you changed any of these files, save it using a different name!

- Delete a job
  - `python RedReaper.py -d <job_name>`
    - Users will be asked to confirm deletion
    - When a job is deleted, the directory under 'jobs' is removed; this includes the job config, list of processed files, and the saved state
    - No processed data is deleted when deleting a job
