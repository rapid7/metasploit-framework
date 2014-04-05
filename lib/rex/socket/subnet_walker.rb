# -*- coding: binary -*-
require 'rex/socket'

module Rex
module Socket

###
#
# This class provides an interface to enumerating a subnet with a supplied
# netmask.
#
###
class SubnetWalker

  #
  # Initializes a subnet walker instance using the supplied subnet
  # information.
  #
  def initialize(subnet, netmask)
    self.subnet  = Socket.resolv_to_dotted(subnet)
    self.netmask = Socket.resolv_to_dotted(netmask)

    reset
  end

  #
  # Resets the subnet walker back to its original state.
  #
  def reset
    self.curr_ip     = self.subnet.split('.')
    self.num_ips     = (1 << (32 - Socket.net2bitmask(self.netmask).to_i))
    self.curr_ip_idx = 0
  end

  #
  # Returns the next IP address.
  #
  def next_ip
    if (curr_ip_idx >= num_ips)
      return nil
    end

    if (curr_ip_idx > 0)
      self.curr_ip[3] = (curr_ip[3].to_i + 1) % 256
      self.curr_ip[2] = (curr_ip[2].to_i + 1) % 256 if (curr_ip[3] == 0)
      self.curr_ip[1] = (curr_ip[1].to_i + 1) % 256 if (curr_ip[2] == 0)
      self.curr_ip[0] = (curr_ip[0].to_i + 1) % 256 if (curr_ip[1] == 0)
    end

    self.curr_ip_idx += 1

    self.curr_ip.join('.')
  end

  #
  # The subnet that is being enumerated.
  #
  attr_reader :subnet
  #
  # The netmask of the subnet.
  #
  attr_reader :netmask
  #
  # The total number of IPs within the subnet.
  #
  attr_reader :num_ips

protected

  attr_writer   :subnet, :netmask, :num_ips # :nodoc:
  attr_accessor :curr_ip, :curr_ip_idx # :nodoc:

end

end
end
