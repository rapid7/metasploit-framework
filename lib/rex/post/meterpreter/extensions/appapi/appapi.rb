# -*- coding: binary -*-
# CorrM @ fb.me/IslamNofl

require 'rex/post/meterpreter/object_aliases'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/extensions/appapi/tlv'
require 'rex/post/meterpreter/extensions/appapi/apps/android_apps'

module Rex
module Post
module Meterpreter
module Extensions
module AppApi

###
#
# Application interface to controle Application in Device
#
###
class AppApi < Extension

  #
  # Initializes an instance of the Application API extension.
  #
  def initialize(client)
    super(client, 'AppApi')

    # Alias the following things on the client object so that they
    # can be directly referenced
    client.register_extension_aliases(
      [
        {
          'name' => 'apps', # => to use like that (client.apps.app_install) => "apps"
          'ext'  => Rex::Post::Meterpreter::Extensions::AppApi::AndroidApps.new(client)
        }

      ])
  end

  #
  # Sets the client instance on a duplicated copy of the supplied class.
  #
  def brand(klass)
    klass = klass.dup
    klass.client = self.client
    return klass
  end
end

end; end; end; end; end
