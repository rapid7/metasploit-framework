
require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptPort do
  valid_values = [ "0",  "1", "80", "65535" ].map{|v|
		# This is bogus, but OptPort doesn't implement #normalize, so it
		# falls back to just returning the original value
		[ v, v ]
	}
  invalid_values = [ "yer mom", "0.1", "-1", "65536" ]

  it_behaves_like "an option", valid_values, invalid_values
end

