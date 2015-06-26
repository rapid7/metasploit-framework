# -*- coding: binary -*-

require 'rex/post/meeterpeter/extensions/lanattacks/tlv'
require 'rex/post/meeterpeter/extensions/lanattacks/dhcp/dhcp'
require 'rex/post/meeterpeter/extensions/lanattacks/tftp/tftp'

module Rex
module Post
module meeterpeter
module Extensions
module Lanattacks

###
#
# This meeterpeter extension can currently run DHCP and TFTP servers
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
              'dhcp' => Rex::Post::meeterpeter::Extensions::Lanattacks::Dhcp::Dhcp.new(client),
              'tftp' => Rex::Post::meeterpeter::Extensions::Lanattacks::Tftp::Tftp.new(client)
            }),
        }
      ])
  end

end

end; end; end; end; end
