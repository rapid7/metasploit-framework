Execute 01_StartAudit.bat as an administrative user. This will attempt to launch the
handler for all known file types. When this process is complete, access the open
ProcMon window and use the Save option from the File menu. Save the output to this
directory as a file named Logfile.CSV and make sure you choose the CSV file type.

Once Logfile.CSV has been created, execute 02_Analyze.bat as an administrative user.
This will attempt to validate each result and generate a list of proof-of-concepts
within the Exploit subdirectory. For the best results, manually review the ProcMon
logs to ensure that various corner cases and other related vulnerabilities are not
missed. 

Have fun!

-HD <hdm[at]metasploit.com>