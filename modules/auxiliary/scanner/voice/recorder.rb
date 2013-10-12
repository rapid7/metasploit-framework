##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'fileutils'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::IAX2

  def initialize
    super(
      'Name'           => 'Telephone Line Voice Scanner',
      'Description'    => 'This module dials a range of phone numbers and records audio from each answered call',
      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE,
      'References'     => [  ]
    )
    register_options([
      OptString.new('TARGETS', [true, "A list of telephone masks in the format of 1-555-555-5XXX, separated by commas"]),
      OptString.new('OUTPUT_PATH', [true, "A local directory to store the resulting audio files"]),
      OptInt.new('CALL_TIME', [true, "The maximum time in seconds to spent on each call (ring + recording)", 52])
    ], self.class)
  end

  def run
    targets = crack_phone_ranges(datastore['TARGETS'].split(","))
    connect

    ::FileUtils.mkdir_p( datastore['OUTPUT_PATH'] )

    targets.each do |number|

      c = create_call
      begin
        ::Timeout.timeout( datastore['CALL_TIME'] ) do
          print_status("Dialing #{number}...")
          r = c.dial(number)
          if not c
            print_error("Failed to call #{number}")
            next
          end
          lstate = c.state
          while c.state != :hangup
            print_status("  Number: #{number}  State: #{c.state}  Frames: #{c.audio_buff.length}  DTMF: '#{c.dtmf}'")
            Rex.sleep(1.0)
          end
        end
      rescue ::Timeout::Error
        # Timeouts are A-OK
      ensure
        c.hangup rescue nil
      end

      print_status("  COMPLETED   Number: #{number}  State: #{c.state}  Frames: #{c.audio_buff.length}  DTMF: '#{c.dtmf}'")

      if c.audio_buff.length > 0
        opath = ::File.join( datastore['OUTPUT_PATH'], "#{number}.raw" )
        cnt   = 0
        ::File.open(opath, 'wb') do |fd|
          c.audio_buff.each do |raw|
            cnt += raw.length
            fd.write(raw)
          end
        end
        print_good("#{number} resulted in #{cnt} bytes of audio saved to #{opath}")
      end
      # Next call
    end
  end

end
