##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/payload/generic'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Generic

  handler module_name: 'Msf::Handler::None'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Custom Payload',
      'Description'   => 'Use custom string or file as payload. Set either PAYLOADFILE or
                PAYLOADSTR.',
      'Author'        => 'scriptjunkie <scriptjunkie[at]scriptjunkie.us>',
      'License'       => MSF_LICENSE,
      'Payload'	    =>
        {
          'Payload' => "" # not really
        }
      ))

    # Register options
    register_options(
      [
        OptString.new('PAYLOADFILE', [ false, "The file to read the payload from" ] ),
        OptString.new('PAYLOADSTR', [ false, "The string to use as a payload" ] )
      ], self.class)
  end

  #
  # Construct the payload
  #
  def generate
    if datastore['ARCH']
      self.arch = actual_arch
    end

    if datastore['PAYLOADFILE']
      IO.read(datastore['PAYLOADFILE'])
    elsif datastore['PAYLOADSTR']
      datastore['PAYLOADSTR']
    end
  end

  # Only accept the "none" encoder
  def compatible_encoders
    encoders = super()
    encoders2 = []
    encoders.each do |encname, encmod|
      encoders2 << [encname, encmod] if encname.include? 'none'
    end

    return encoders2
  end

end
