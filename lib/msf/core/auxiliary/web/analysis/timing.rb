# -*- coding: binary -*-
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# https://metasploit.com/framework/
##

module Msf

module Auxiliary::Web
module Analysis::Timing

  TIMING_OPTIONS =  {
    # stub to be replaced by delay * multi
    :stub =>  '__TIME__',

    # stub = delay * multi
    :multi => 1,

    # delay in seconds to attempt to introduce
    :delay => 5
  }

  #
  # Performs timeout/time-delay analysis and logs an issue should there be one.
  #
  # Fuzzer must provide:
  #   - #seeds_for -- Array of Strings with server-side code which, when interpreted,
  #       will cause a delay in response. Must include 'stub'.
  #
  # Here's how it goes:
  # * Ensures that the server is responsive.
  # * Injects the seed and makes sure that the expected delay has been successfully introduced.
  # * Ensures that the server is responsive -- blocks until the attack has worn off.
  # * Increases the original delay and makes sure that the expected delay has been successfully introduced.
  # * Ensures that the server is responsive-- blocks until the attack has worn off.
  # * Logs the vulnerability.
  #
  # opts - Options Hash (default: {})
  #        :timeout - Integer amount of seconds to wait for the request to complete (default: 5)
  #        :stub - String stub to be replaced by delay * multi (default: __TIME__)
  #        :multi - Integer multiplier (stub = timeout * multi) (default: 1)
  #
  def timeout_analysis( opts = {} )
    opts = TIMING_OPTIONS.merge( opts )

    multi   = opts[:multi]
    stub    = opts[:stub]

    return if fuzzed? :type => :timing
    fuzzed :type => :timing

    permutations.each do |p|
      timeout = opts[:delay]

      seed    = p.altered_value.dup
      payload = fuzzer.payloads.select{ |pl| seed.include?( pl ) }.max_by(&:size)

      # 1st pass, make sure the webapp is responsive
      if_responsive do
        # 2nd pass, see if we can manipulate the response times
        timeout += 1
        p.altered_value = seed.gsub( stub, (timeout * multi).to_s )

        p.if_unresponsive( timeout - 1 ) do
          # 3rd pass, make sure that the previous step wasn't a fluke (like a dead web server)
          if_responsive do
            # 4th pass, increase the delay and timeout to make sure that we are the ones
            # manipulating the webapp and this isn't all a coincidence
            timeout *= 2
            timeout += 1
            p.altered_value = seed.gsub( stub, (timeout * multi).to_s )

            p.if_unresponsive( timeout - 1 ) do
              # log it!
              fuzzer.process_vulnerability( p, 'Manipulatable response times.',
                :payload => payload.gsub( stub, (timeout * multi).to_s ) )
            end
          end
        end
      end
    end
  end

  def responsive?( timeout = 120 )
    !submit( :timeout => timeout ).timed_out?
  end

  def responsive_async?( timeout = 120, &callback )
    submit_async( :timeout => timeout ) { |r| callback.call !r.timed_out? }
  end

  def if_responsive( timeout = 120, &callback )
    responsive_async?( timeout ) { |b| callback.call if b }
  end

  def if_unresponsive( timeout = 120, &callback )
    responsive_async?( timeout ) { |b| callback.call if !b }
  end

end
end
end
