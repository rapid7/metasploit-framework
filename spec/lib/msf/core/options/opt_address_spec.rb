
require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptAddress do
	valid_values = [
		"192.0.2.0", "127.0.0.1", "2001:db8::", "::1"
	# Normalized values are just the original value
	].map{|a| { :value => a, :normalized => a } }

	invalid_values = [
		# Too many dots
		{ :value => "192.0.2.0.0" },
		# Not enough
    { :pending => "Redmine #7537", :value => "192.0.2" }
	]

	it_behaves_like "an option", valid_values, invalid_values
end


