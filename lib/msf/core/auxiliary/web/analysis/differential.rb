##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

module Msf

module Auxiliary::Web
module Analysis::Differential

  DIFFERENTIAL_OPTIONS =  {
    # amount of refinement iterations
    :precision => 2
  }

  #
  # Performs differential analysis and logs an issue should there be one.
  #
  # Fuzzer must provide:
  #   - #boolean_seeds_for - array of boolean injection strings
  #	   (these are supposed to not alter the webapp behavior when interpreted)
  #   - #fault_seeds_for - array of fault injection strings
  #	   (these are supposed to force erroneous conditions when interpreted)
  #
  # Here's how it goes:
  # * let _default_ be the default/original response
  # * let _fault_   be the response of the fault injection
  # * let _bool_	be the response of the boolean injection
  #
  # A vulnerability is logged if:
  #	 default == bool AND bool.code == 200 AND fault != bool
  #
  # The "bool" response is also checked in order to determine if it's a custom 404,
  # if it is it'll be skipped.
  #
  # @param	[Hash]	  opts	  Options Hash (default: {})
  #								   :precision - amount of refinement iterations (default: 2)
  #
  def differential_analysis( opts = {}, &block )
    opts = DIFFERENTIAL_OPTIONS.merge( opts )

    return if fuzzed? :type => :differential
    fuzzed :type => :differential

    # don't continue if there's a missing value
    params.values.each { |val| return if !val || val.empty? }

    responses = {
      # will hold the original, default, response that results from submitting
      :orig => nil,

      # will hold responses of boolean injections
      :good => {},

      # will hold responses of fault injections
      :bad =>  {}
    }

    # submit the element, as is, opts[:precision] amount of times and
    # rdiff the responses in order to arrive to a refined response without
    # any superfluous dynamic content
    opts[:precision].times do
      # get the default responses
      submit_async do |res|
        responses[:orig] ||= res.body.to_s
        # remove context-irrelevant dynamic content like banners and such
        responses[:orig] = Rex::Text.refine( responses[:orig], res.body.to_s )
      end
    end

    # perform fault injection opts[:precision] amount of times and
    # rdiff the responses in order to arrive to a refined response without
    # any superfluous dynamic content
    opts[:precision].times do
      params.map do |name, value|
        fuzzer.fault_seeds_for( value ).map { |seed| permutation_for( name, seed ) }
           end.flatten.uniq.each do |elem|

        # submit the mutation and store the response
        elem.submit_async do |res|
                responses[:bad][elem.altered] ||= res.body.to_s.dup

          # remove context-irrelevant dynamic content like banners and such
          # from the error page
          responses[:bad][elem.altered] =
            Rex::Text.refine( responses[:bad][elem.altered], res.body.to_s.dup )
        end
          end
    end

    # get injection variations that will not affect the outcome of the query
    params.map do |name, value|
      fuzzer.boolean_seeds_for( value ).map { |seed| permutation_for( name, seed ) }
    end.flatten.uniq.each do |elem|

      # submit the mutation and store the response
      elem.submit_async do |res|
        responses[:good][elem.altered] ||= []
        # save the response and some data for analysis
        responses[:good][elem.altered] << {
          'res'  => res,
          'elem' => elem.dup
        }
      end
    end

    http.after_run do
      responses[:good].keys.each do |key|
        responses[:good][key].each do |res|

          # if default_response_body == bool_response_body AND
          #	fault_response_body != bool_response_body AND
          #	bool_response_code == 200
          if responses[:orig] == res['res'].body &&
            responses[:bad][key] != res['res'].body &&
            res['res'].code.to_i == 200

            # check to see if the current boolean response we're analyzing
            # is a custom 404 page
            http.if_not_custom_404( action, res['res'].body ) do
              # if this isn't a custom 404 page then it means that
              # the element is vulnerable, so go ahead and log the issue
              fuzzer.process_vulnerability( res['elem'], 'Boolean manipulation.' )
            end
          end
        end
      end
    end
  end

end
end
end
