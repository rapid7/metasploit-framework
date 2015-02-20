# -*- coding: binary -*-
require 'rex/proto/iax2/client'

module Msf

###
#
# This module provides methods for working with the IAX2 protocol
#
###
module Auxiliary::IAX2

  #
  # Initializes an instance of an auxiliary module that uses IAX2
  #

  def initialize(info = {})
    super

    register_options(
      [
        OptAddress.new('IAX_HOST', [true, 'The IAX2 server to communicate with']),
        OptPort.new('IAX_PORT',    [true, 'The IAX2 server port', 4569]),
        OptString.new('IAX_USER',  [false, 'An optional IAX2 username']),
        OptString.new('IAX_PASS',  [false, 'An optional IAX2 password']),
        OptString.new('IAX_CID_NAME',  [false, 'The default caller ID name', '']),
        OptString.new('IAX_CID_NUMBER',  [true, 'The default caller ID number', '15555555555'])
      ], Msf::Auxiliary::IAX2 )

    register_advanced_options(
      [
        OptBool.new('IAX_DEBUG', [false, 'Enable IAX2 debugging messages', false])
      ], Msf::Auxiliary::IAX2 )

  end

  def connect
    @iax.shutdown if @iax
    @iax = Rex::Proto::IAX2::Client.new(
      :server_host    => datastore['IAX_HOST'],
      :username       => datastore['IAX_USER'],
      :password       => datastore['IAX_PASS'],
      :caller_name    => datastore['IAX_CID_NAME'],
      :caller_number  => datastore['IAX_CID_NUMBER'],
      :debugging      => datastore['IAX_DEBUG'],
      :context        => {
        'Msf'        => framework,
        'MsfExploit' => self
      }
    )
    @iax_reg = @iax.create_call()
    r = @iax_reg.register
    if not r
      @iax.shutdown
      @iax = nil
      raise RuntimeError, "Failed to register with the server"
    end
  end

  def create_call
    if not @iax
      raise RuntimeError, "No active IAX2 connection"
    end
    @iax.create_call
  end

  def cleanup
    super
    @iax.shutdown if @iax
  end

  # General purpose phone number mangling routines
  # Convert 123456XXXX to an array of expanded numbers
  def crack_phone_range(range)
    crack_phone_ranges([range])
  end

  def crack_phone_ranges(masks)
    res = {}
    masks.each do |mask|
      mask = mask.strip

      if(mask.index(':'))
        next if mask.index('X')
        rbeg,rend = mask.split(':').map{|c| c.gsub(/[^\d]/, '').to_i }
        rbeg.upto(rend) do |n|
          res[n.to_s] = {}
        end
        next
      end

      incdigits = 0
      mask.each_char do |c|
        incdigits += 1 if c =~ /^[X#]$/i
      end

      max = (10**incdigits)-1

      (0..max).each do |num|
        number = mask.dup # copy the mask
        numstr = sprintf("%0#{incdigits}d", num) # stringify our incrementing number
        j = 0 # index for numstr
        for i in 0..number.length-1 do # step through the number (mask)
          if number[i].chr =~ /^[X#]$/i
            number[i] = numstr[j] # replaced masked indexes with digits from incrementing number
            j += 1
          end
        end
        res[number] = {}
      end

    end

    return res.keys.sort
  end

end
end

