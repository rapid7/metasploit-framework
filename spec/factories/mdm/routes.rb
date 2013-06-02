FactoryGirl.define do
	factory :mdm_route, :class => Mdm::Route do
		netmask { generate :mdm_route_netmask }
		subnet { generate :mdm_route_subnet }

		#
		# Associations
		#
		association :session, :factory => :mdm_session
	end

	sequence :mdm_route_netmask do |n|
		bits = 32
		bitmask = n % bits

		[ (~((2 ** (bits - bitmask)) - 1)) & 0xffffffff ].pack('N').unpack('CCCC').join('.')

		bits = 32
		shift = n % bits
		mask_range = 2 ** bits
		full_mask = mask_range - 1

		integer_netmask = (full_mask << shift)
		formatted_netmask = [integer_netmask].pack('N').unpack('CCCC').join('.')

		formatted_netmask
	end

	sequence :mdm_route_subnet do |n|
		class_c_network = n % 255

    "192.168.#{class_c_network}.0"
	end
end