# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for Distributed Reflective Denial of Service (DRDoS) attacks
#
###
module Auxiliary::DRDoS

  def initialize(info = {})
    super
    register_advanced_options(
      [
        OptAddress.new('SRCIP', [false, 'Use this source IP']),
        OptInt.new('NUM_REQUESTS', [false, 'Number of requests to send', 1]),
      ], self.class)
  end

  def setup
    super
    if spoofed? && datastore['NUM_REQUESTS'] < 1
      raise Msf::OptionValidateError.new(['NUM_REQUESTS']), 'The number of requests must be >= 1'
    end
  end

  def prove_amplification(response_map)
    vulnerable = false
    proofs = []
    response_map.each do |request, responses|
      responses ||= []
      this_proof = ''

      # compute packet amplification
      if responses.size > 1
        vulnerable = true
        this_proof += "#{responses.size}x packet amplification"
      else
        this_proof += 'No packet amplification'
      end

      this_proof += ' and '

      # compute bandwidth amplification
      total_size = responses.map(&:size).reduce(:+)
      bandwidth_amplification = total_size - request.size
      if bandwidth_amplification > 0
        vulnerable = true
        if request.size == 0
          multiplier = total_size
        else
          multiplier = total_size / request.size
        end
        this_proof += "a #{multiplier}x, #{bandwidth_amplification}-byte bandwidth amplification"
      else
        this_proof += 'no bandwidth amplification'
      end

      # TODO (maybe): show the request and responses in more detail?
      proofs << this_proof
    end

    [ vulnerable, proofs.join(', ') ]
  end

  def spoofed?
    !datastore['SRCIP'].nil?
  end

end
end
