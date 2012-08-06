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
		precision: 2
	}

	#
	# Performs differential analysis and logs an issue should there be one.
	#
	#    opts = {
	#        :precision => 3,
	#        :faults    => [ 'fault injections' ],
	#        :bools     => [ 'boolean injections' ]
	#    }
	#
	#    element.rdiff_analysis( opts )
	#
	# Here's how it goes:
	# * let _default_ be the default/original response
	# * let _fault_   be the response of the fault injection
	# * let _bool_    be the response of the boolean injection
	#
	# A vulnerability is logged if:
	#     default == bool AND bool.code == 200 AND fault != bool
	#
	# The "bool" response is also checked in order to determine if it's a custom 404, if it is it'll be skipped.
	#
	# If a block has been provided analysis and logging will be delegated to it.
	#
	# @param    [Hash]      opts        available options:
	#                                   * :format -- as seen in {Arachni::Parser::Element::Mutable::MUTATION_OPTIONS}
	#                                   * :precision -- amount of rdiff iterations
	#                                   * :faults -- array of fault injection strings (these are supposed to force erroneous conditions when interpreted)
	#                                   * :bools -- array of boolean injection strings (these are supposed to not alter the webapp behavior when interpreted)
	# @param    [Block]     block      block to be used for custom analysis of responses; will be passed the following:
	#                                   * injected string
	#                                   * audited element
	#                                   * default response body
	#                                   * boolean response
	#                                   * fault injection response body
	#
	def differential_analysis( opts = {}, &block )
		opts = DIFFERENTIAL_OPTIONS.merge( opts )

		# don't continue if there's a missing value
		params.values.each { |val| return if !val || val.empty? }

		responses = {
			# will hold the original, default, response that results from submitting
			orig: nil,

			# will hold responses of boolean injections
			good: {},

			# will hold responses of fault injections
			bad:  {}
		}

		# submit the element, as is, opts[:precision] amount of times and
		# rdiff the responses in order to arrive to a refined response without
		# any superfluous dynamic content
		opts[:precision].times {
			# get the default responses
			res = submit
			responses[:orig] ||= res.body.to_s
			# remove context-irrelevant dynamic content like banners and such
			responses[:orig] = Rex::Text.refine( responses[:orig], res.body.to_s )
		}

		# perform fault injection opts[:precision] amount of times and
		# rdiff the responses in order to arrive to a refined response without
		# any superfluous dynamic content
		opts[:precision].times {
			params.map do |name, value|
				fuzzer.fault_seeds_for( value ).map { |seed| permutation_for( name, seed ) }
			end.flatten.uniq.each do |elem|
				# submit the mutation and store the response
				res = elem.submit

				responses[:bad][elem.altered] ||= res.body.to_s.dup

				# remove context-irrelevant dynamic content like banners and such
				# from the error page
				responses[:bad][elem.altered] =
					Rex::Text.refine( responses[:bad][elem.altered], res.body.to_s.dup )
			end
		}

		# get injection variations that will not affect the outcome of the query
		params.map do |name, value|
			fuzzer.boolean_seeds_for( value ).map { |seed| permutation_for( name, seed ) }
		end.flatten.uniq.each do |elem|
			# submit the mutation and store the response
			res = elem.submit
			responses[:good][elem.altered] ||= []
			# save the response and some data for analysis
			responses[:good][elem.altered] << {
				'res'  => res,
				'elem' => elem
			}
		end

		responses[:good].keys.each do |key|
			responses[:good][key].each do |res|
				#puts 'Default'
				#puts responses[:orig]
				#
				#puts '--'
				#
				#puts 'Bool'
				#puts res['res'].body
				#
				#puts '--'
				#
				#puts 'Fault'
				#puts responses[:bad][key]
				#
				#puts '---------------------'

				#p responses[:orig] == res['res'].body
				#p responses[:bad][key] != res['res'].body
				#p res['res'].code == 200
				#p res['res'].code
				#puts '---------------------'

				# if default_response_body == bool_response_body AND
				#    fault_response_body != bool_response_body AND
				#    bool_response_code == 200
				if responses[:orig] == res['res'].body &&
					responses[:bad][key] != res['res'].body &&
					res['res'].code.to_i == 200

					# check to see if the current boolean response we're analyzing
					# is a custom 404 page
					if !fuzzer.custom_404?( action, res['res'].body )
						# if this isn't a custom 404 page then it means that
						# the element is vulnerable, so go ahead and log the issue
						fuzzer.process_vulnerability( res['elem'], 'Manipulatable responses.',
						                              :payload => res['elem'].altered_value )
					end
				end

			end
		end
	end

end
end
end
