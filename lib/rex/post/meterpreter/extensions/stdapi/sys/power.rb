#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/process'
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys

###
#
# This class provides access to the power of the remote machine (reboot, etc).
#
###
class Power

  class <<self
    attr_accessor :client
  end

  #
  # Calls ExitWindows on the remote machine with the supplied parameters.
  #
  def Power._exitwindows(flags, reason = 0, force = 0) # :nodoc:
    request = Packet.create_request('stdapi_sys_power_exitwindows')

    flags |= EWX_FORCEIFHUNG if force == 1
    flags |= EWX_FORCE       if force == 2

    request.add_tlv(TLV_TYPE_POWER_FLAGS, flags);
    request.add_tlv(TLV_TYPE_POWER_REASON, reason);

    response = client.send_request(request)

    return response
  end

  #
  # Reboots the remote machine.
  #
  def Power.reboot(force = 0, reason = 0)
    self._exitwindows(EWX_REBOOT, reason, force)
  end

  #
  # Shuts down the remote machine.
  #
  def Power.shutdown(force = 0, reason = 0)
    self._exitwindows(EWX_POWEROFF, reason, force)
  end

end

end end end end end end
