##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/accounts'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Accounts

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather Logged On User Enumeration (Registry)',
        'Description'   => %q{ This module will enumerate current and recently logged on Windows users},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
    register_options(
      [
        OptBool.new('CURRENT', [ true, 'Enumerate currently logged on users', true]),
        OptBool.new('RECENT' , [ true, 'Enumerate Recently logged on users' , true])
      ], self.class)

  end


  def ls_logged
    sids = []
    sids << registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
    tbl = Rex::Ui::Text::Table.new(
      'Header'  => "Recently Logged Users",
      'Indent'  => 1,
      'Columns' =>
      [
        "SID",
        "Profile Path"
      ])
    sids.flatten.map do |sid|
      profile_path = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\#{sid}","ProfileImagePath")
      tbl << [sid,profile_path]
    end
    print_line("\n" + tbl.to_s + "\n")
    store_loot("host.users.recent", "text/plain", session, tbl.to_s, "recent_users.txt", "Recent Users")
  end


  def ls_current
    key_base, username = "",""
    tbl = Rex::Ui::Text::Table.new(
      'Header'  => "Current Logged Users",
      'Indent'  => 1,
      'Columns' =>
      [
        "SID",
        "User"
      ])
    registry_enumkeys("HKU").each do |maybe_sid|
      # There is junk like .DEFAULT we want to avoid
      if maybe_sid =~ /^S(?:-\d+){2,}$/
        info = resolve_sid(maybe_sid)

        if !info.nil? && info[:type] == :user
          username = info[:domain] << '\\' << info[:name]

          tbl << [maybe_sid,username]
        end
      end
    end

    print_line("\n" + tbl.to_s + "\n")
    p = store_loot("host.users.active", "text/plain", session, tbl.to_s, "active_users.txt", "Active Users")
    print_status("Results saved in: #{p}")
  end

  def run
    print_status("Running against session #{datastore['SESSION']}")

    if datastore['CURRENT']
      ls_current
    end

    if datastore['RECENT']
      ls_logged
    end

  end
end
