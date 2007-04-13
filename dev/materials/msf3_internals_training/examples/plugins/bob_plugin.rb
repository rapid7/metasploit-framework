module Msf
class Plugin::Bob < Msf::Plugin
	module BobExtension
		def bob
			"bob"
		end
	end
	def initialize(framework, options)
		framework.extend(BobExtension)
	end
end
end
