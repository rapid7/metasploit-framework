require 'Msf/Core'

###
#
# Target
# ------
#
# A target for an exploit.
#
###
class Msf::Module::Target

	#
	# Serialize from an array to a Target instance
	#
	def self.from_a(ary)
		return nil if (ary.length < 2)

		t      = self.new(ary.shift, ary.shift)
		t.opts = ary

		return t
	end

	#
	# Transforms the supplied source into an array of Target's
	#
	def self.transform(src)
		Rex::Transformer.transform(src, Array, [ self, String ], 'Target')
	end

	def initialize(name, platforms, *opts)
		self.name      = name
		self.platforms = Msf::Module::PlatformList.from_a(platforms)
		self.opts      = opts
	end

end

