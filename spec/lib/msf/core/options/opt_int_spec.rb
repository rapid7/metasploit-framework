
require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptInt do
  valid_values = [
    "1", "10", "0", 
    #"-1", # Negatives don't work
  ].map{|v| [ v, v.to_i ] }
  valid_values.push([ "0x10", 16 ])
  invalid_values = [
    #"yer mom", # to_i makes this 0
    #"0.1", # to_i makes this 0
  ]

  it_behaves_like "an option", valid_values, invalid_values
end


