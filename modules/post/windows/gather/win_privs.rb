##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Privileges Enumeration',
      'Description'   => %q{
        This module will print if UAC is enabled, and if the current account is
        ADMIN enabled. It will also print UID, foreground SESSION ID, is SYSTEM status
        and current process PRIVILEGES.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Merlyn Cousins <drforbin6[at]gmail.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run
    usr_tbl = Rex::Ui::Text::Table.new(
      'Header'  => 'Current User',
      'Indent'  => 1,
      'Columns' => ['Is Admin', 'Is System', 'UAC Enabled', 'Foreground ID', 'UID']
    )

    privs_tbl = Rex::Ui::Text::Table.new(
      'Header' =>"Windows Privileges",
      'Indent' => 1,
      'Columns' => ['Name']
    )

    # Gather data
    uac   = is_uac_enabled? ? 'True' : 'False'
    admin = is_admin? ? 'True' : 'False'
    sys   = is_system? ? 'True' : 'False'
    uid   = client.sys.config.getuid.inspect
    begin
      # Older OS might not have this (min support is XP)
      fid = client.railgun.kernel32.WTSGetActiveConsoleSessionId["return"]
    rescue
      fid = 'N/A'
    end
    privs = client.sys.config.getprivs

    # Store in tables
    usr_tbl << [admin, sys, uac, fid, uid]
    privs.each do |priv|
      privs_tbl << [priv]
    end

    # Show tables
    print_line(usr_tbl.to_s)
    print_line(privs_tbl.to_s)
  end

end
