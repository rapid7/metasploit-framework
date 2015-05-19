# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/lanattacks/tlv'
require 'rex/post/meterpreter/extensions/lanattacks/dhcp/dhcp'
require 'rex/post/meterpreter/extensions/lanattacks/tftp/tftp'

module Rex
module Post
module Meterpreter
module Extensions
module Lanattacks

###
#
# This meterpreter extension can currently run DHCP and TFTP servers
#
###
class Lanattacks < Extension

  #
  # Initializes an instance of the lanattacks extension.
  #
  def initialize(client)
    super(client, 'lanattacks')

    # Alias the following things on the client object so that they
    # can be directly referenced
    client.register_extension_aliases(
      [
        {
          'name' => 'lanattacks',
          'ext'  => ObjectAliases.new(
            {
              'dhcp' => Rex::Post::Meterpreter::Extensions::Lanattacks::Dhcp::Dhcp.new(client),
              'tftp' => Rex::Post::Meterpreter::Extensions::Lanattacks::Tftp::Tftp.new(client)
            }),
        }
      ])
  end

end

end; end; end; end; end
