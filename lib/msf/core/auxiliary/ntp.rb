# -*- coding: binary -*-
require 'rex/proto/ntp'
require 'msf/core/exploit'
module Msf

###
#
# This module provides methods for working with NTP
#
###
module Auxiliary::NTP

  include Exploit::Capture
  include Auxiliary::Scanner

  #
  # Initializes an instance of an auxiliary module that uses NTP
  #

  def initialize(info = {})
    super
    register_options(
    [
      Opt::RPORT(123),
    ], self.class)

    register_advanced_options(
      [
        OptInt.new('VERSION', [true, 'Use this NTP version', 2]),
        OptInt.new('IMPLEMENTATION', [true, 'Use this NTP mode 7 implementation', 3])
      ], self.class)
  end

  # Called for each IP in the batch
  def scan_host(ip)
    if spoofed?
      datastore['ScannerRecvWindow'] = 0
      scanner_spoof_send(@probe, ip, datastore['RPORT'], datastore['SRCIP'], datastore['NUM_REQUESTS'])
    else
      scanner_send(@probe, ip, datastore['RPORT'])
    end
  end
end
end
