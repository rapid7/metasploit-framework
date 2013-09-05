#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/object_aliases'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/extensions/android/common/common'
require 'rex/post/meterpreter/extensions/android/root/root'
require 'rex/post/meterpreter/extensions/android/tlv'


module Rex
module Post
module Meterpreter
module Extensions
module Android

class Android < Extension

  #
  # Initializes an instance of the standard API extension.
  #
  def initialize(client)
    super(client, 'android')

    # Alias the following things on the client object so that they
    # can be directly referenced
    client.register_extension_aliases(
      [
        {
          'name' => 'common',
          'ext'  => Rex::Post::Meterpreter::Extensions::Android::Common::Common.new(client)
        },
        {
          'name' => 'root',
          'ext'  => Rex::Post::Meterpreter::Extensions::Android::Root::Root.new(client)
        }
      ])
  end

  
end

end; end; end; end; end
