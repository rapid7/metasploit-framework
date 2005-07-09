require 'msf/core'

###
#
# Reference
# ---------
#
# A reference to some sort of information.
#
###
class Msf::Module::Reference

	def self.from_s(str)
		return self.new(str)
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
class Msf::Module::SiteReference < Msf::Module::Reference

	#
	# Class method that translates a URL into a site reference instance
	#
	def self.from_s(str)
		instance = self.new

		if (instance.from_s(str) == false)
			return nil
		end

		return instance
	end

	def self.from_a(ary)
		return nil if (ary.length < 2)

		self.new(ary[0], ary[1])
	end

	#
	# Initialize the site reference
	#
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
			self.site  = in_site
			self.site += " (#{in_ctx_id.to_s})" if (in_ctx_id)
		end
	end

	#
	# Returns the absolute site URL
	#
	def to_s
		return site || ''
	end

	#
	# Serializes a site URL string
	#
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


