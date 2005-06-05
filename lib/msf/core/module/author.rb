require 'Msf/Core'

###
#
# Author
# ------
#
# This data type represents an author of a piece of code in either
# the framework, a module, a script, or something entirely unrelated.
#
###
class Msf::Module::Author
	#
	# Class method that translates a string to an instance of the Author class,
	# if it's of the right format, and returns the Author class instance
	#
	def self.from_s(str)
		instance = self.new

		# If the serialization fails...
		if (instance.from_s(str) == false)
			return nil
		end

		return instance
	end

	#
	# Transforms the supplied source into an array of authors
	#
	def self.transform(src)
		Rex::Transformer.transform(src, Array, [ self ], 'Author')
	end

	def initialize(name = nil, email = nil)
		self.name  = name
		self.email = email
	end

	#
	# Serialize the author object to a string in form:
	#
	# name <email>
	#
	def to_s
		str = "#{name}"

		if (email != nil)
			str += " <#{email}>"
		end

		return str
	end

	#
	# Translate the author from the supplied string which may
	# have either just a name or also an email address
	#
	def from_s(str)

		# List of known framework authors that can be referred by just name
		known_authors =
			{
				'hdm'       => 'hdm@metasploit.com',
				'H D Moore' => 'hdm@metasploit.com',
				'spoonm'    => 'spoonm@gmail.com',
				'skape'     => 'mmiller@hick.org',
				'vlad902'   => 'vlad902@gmail.com'
			}

		# Make fix up this regex to be a bit better...I suck at regex
		m = /^([A-Za-z0-9 _]*?) <(.*?)>/.match(str)

		if (m != nil)
			self.name  = m[1]
			self.email = m[2]
		else
			self.email = known_authors[str]

			if (self.email != nil)
				self.name = str
			else
				return false
			end
		end

		return true
	end

	attr_accessor :name, :email
end
