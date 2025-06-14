##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 0

  include Msf::Payload::Single
  include Msf::Payload::Generic

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Custom Payload',
        'Description' => %q{
          Use custom string or file as payload. Set either PAYLOADFILE or
          PAYLOADSTR.
        },
        'Author' => 'scriptjunkie <scriptjunkie[at]scriptjunkie.us>',
        'License' => MSF_LICENSE,
        'Payload' => {
          'Payload' => '' # not really
        }
      )
    )

    # Register options
    register_options(
      [
        OptString.new('PAYLOADFILE', [ false, 'The file to read the payload from' ]),
        OptString.new('PAYLOADSTR', [ false, 'The string to use as a payload' ])
      ]
    )
  end

  #
  # Construct the payload
  #
  def generate(_opts = {})
    if datastore['ARCH']
      self.arch = actual_arch
    end

    if datastore['PAYLOADSTR']
      datastore['PAYLOADSTR']
    elsif datastore['PAYLOADFILE']
      File.binread(datastore['PAYLOADFILE'])
    else
      ''
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
