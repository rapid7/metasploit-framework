
require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptAddressRange do
	# Normalized values are just the original value for OptAddressRange
	valid_values = [
		{ :value => "192.0.2.0/24",    :normalized => "192.0.2.0/24" },
		{ :value => "192.0.2.0-255",   :normalized => "192.0.2.0-255" },
		{ :value => "192.0.2.0,1-255", :normalized => "192.0.2.0,1-255" },
		{ :value => "192.0.2.*",       :normalized => "192.0.2.*" },
		{ :value => "192.0.2.0-192.0.2.255", :normalized => "192.0.2.0-192.0.2.255" },
	]
	invalid_values = [
		# Too many dots
		{ :value => "192.0.2.0.0" },
		{ :value => "192.0.2.0.0,1" },
		{ :value => "192.0.2.0.0,1-2" },
		{ :pending => "Redmine #7536", :value => "192.0.2.0.0/24" },
		# Not enough dots
		{ :value => "192.0.2" },
		{ :value => "192.0.2,1" },
		{ :value => "192.0.2,1-2" },
		{ :pending => "Redmine #7536", :value => "192.0.2/24" },
		# Can't mix ranges and CIDR
		{ :value => "192.0.2.0,1/24" },
		{ :value => "192.0.2.0-1/24" },
		{ :value => "192.0.2.0,1-2/24" },
		{ :value => "192.0.2.0/1-24" },
		{ :value => "192.0.2.0-192.0.2.1-255", },
	]

	it_behaves_like "an option", valid_values, invalid_values
end


