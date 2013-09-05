##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

module Msf

module Auxiliary::Web
module Analysis::Taint

  #
  # Injects taints into the element parameters.
  #
  # Fuzzer must provide:
  #   - #seeds_for
  #   - #find_proof
  #
  # opts - Options Hash (default: {})
  #
  def taint_analysis( opts = {} )
    return if fuzzed? :type => :taint
    fuzzed :type => :taint

    # if we get a result without injecting anything then bail out to avoid
    # an FP
    return if fuzzer.find_proof( submit, self )

    fuzz_async do |response, permutation|
      next if !response || !(proof = fuzzer.find_proof( response, permutation ))
      fuzzer.process_vulnerability( permutation, proof )
    end
  end

end
end
end
