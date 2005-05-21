module Msf

###
#
# Author
# ------
#
# This data type represents an author of a piece of code in either
# the framework, a module, a script, or something entirely unrelated.
#
###
class Author

	# Class method that translates a string to an instance of the Author class,
	# if it's of the right format, and returns the Author class instance
	def Author.from_s(str)
		instance = Author.new

		# If the serialization fails...
		if (instance.from_s(str) == false)
			return nil
		end

		return instance
	end

	def initialize(name = nil, email = nil)
		self.name  = name
		self.email = email
	end

	# Serialize the author object to a string in form:
	#
	# name <email>
	def to_s
		str = "#{name}"

		if (email != nil)
			str += " <#{email}>"
		end

		return str
	end

	# Translate the author from the supplied string which may
	# have either just a name or also an email address
	def from_s(str)

		# List of known framework authors that can be referred by just name
		known_authors =
			{
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

###
#
# Reference
# ---------
#
# A reference to some sort of information.
#
###
class Reference

	def Reference.from_s(str)
		return Reference.new(str)
	end

	def initialize(in_str)
		self.str = in_str
	end

	def to_s
		return self.str
	end

	def from_s(in_str)
		self.str = in_str
	end

	attr_reader :str

protected

	attr_writer :str

end

###
#
# SiteReference
# -------------
#
# A reference to a website.
#
###
class SiteReference < Reference

	# Class method that translates a URL into a site reference instance
	def SiteReference.from_s(str)
		instance = SiteReference.new

		if (instance.from_s(str) == false)
			return nil
		end

		return instance
	end

	# Initialize the site reference
	def initialize(in_site = nil, in_ctx_id = nil)
		self.ctx_id = in_ctx_id

		if (in_site == 'OSVDB')
			self.site = 'http://www.osvdb.org/' + in_ctx_id.to_s
		elsif (in_site == 'CVE')
			self.site = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=' + in_ctx_id.to_s
		elsif (in_site == 'BID')
			self.site = 'http://www.securityfocus.com/bid/' + in_ctx_id.to_s
		elsif (in_site == 'MSB')
			self.site = 'http://www.microsoft.com/technet/security/bulletin/' + in_ctx_id.to_s + '.mspx'
		else
			self.site = in_site
		end
	end

	# Returns the absolute site URL
	def to_s
		return site || ''
	end

	# Serializes a site URL string
	def from_s(str)
		if (/(http:\/\/|https:\/\/|ftp:\/\/)/.match(str))
			self.site = str
		else
			return false
		end

		return true
	end

	attr_reader :site, :ctx_id

protected

	attr_writer :site, :ctx_id

end

end
