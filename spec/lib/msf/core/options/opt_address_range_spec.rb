
require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptAddressRange do
	# Normalized values are just the original value for OptAddressRange
	valid_values = [
		"192.0.2.0/24",
		"192.0.2.0-255",
		"192.0.2.0,1-255",
		"192.0.2.*",
		"192.0.2.0-192.0.2.255",
	].map{|a| [a, a]}
	invalid_values = [
		# Too many dots
		"192.0.2.0.0",
		"192.0.2.0.0,1",
		"192.0.2.0.0,1-2",
		# CIDR apparently doesn't validate before sending to addr_atoi
		#"192.0.2.0.0/24",
		# Not enough dots
		"192.0.2",
		"192.0.2,1",
		"192.0.2,1-2",
		# CIDR apparently doesn't validate before sending to addr_atoi
		#"192.0.2/24", # Not enough dots, cidr
		# Can't mix ranges and CIDR
		"192.0.2.0,1/24",
		"192.0.2.0-1/24",
		"192.0.2.0,1-2/24",
	]

	it_behaves_like "an option", valid_values, invalid_values
end


