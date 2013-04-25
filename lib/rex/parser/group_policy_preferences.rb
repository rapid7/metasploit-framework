# -*- coding: binary -*-
#

module Rex
module Parser

# This is a parser for the Windows Group Policy Preferences file
# format. It's used by modules/post/windows/gather/credentials/gpp.rb
# and uses REXML (as opposed to Nokogiri) for its XML parsing.
# See: http://msdn.microsoft.com/en-gb/library/cc232587.aspx
class GPP

	require 'rexml/document'

	def self.parse(data)
		xml = REXML::Document.new(data).root
		results = []
		xml.elements.to_a("//Properties").each do |node|
			epassword = node.attributes['cpassword']
			next if epassword.to_s.empty?
			pass = self.decrypt(epassword)

			user = node.attributes['runAs'] if node.attributes['runAs']
			user = node.attributes['accountName'] if node.attributes['accountName']
			user = node.attributes['username'] if node.attributes['username']
			user = node.attributes['userName'] if node.attributes['userName']
			user = node.attributes['newName'] unless node.attributes['newName'].blank?
			changed = node.parent.attributes['changed']

			# Printers and Shares
			path = node.attributes['path']

			# Datasources
			dsn = node.attributes['dsn']
			driver = node.attributes['driver']

			# Tasks
			app_name = node.attributes['appName']

			# Services
			service = node.attributes['serviceName']

			# Groups
			expires = node.attributes['expires']
			never_expires = node.attributes['neverExpires']
			disabled = node.attributes['acctDisabled']

			result = {
				:USER => user,
				:PASS => pass,
				:CHANGED => changed
			}

			result.merge!({ :EXPIRES => expires }) unless expires.blank?
			result.merge!({ :NEVER_EXPIRE => never_expires }) unless never_expires.blank?
			result.merge!({ :DISABLED => disabled }) unless disabled.blank?
			result.merge!({	:PATH => path }) unless path.blank?
			result.merge!({ :DATASOURCE => dsn }) unless dsn.blank?
			result.merge!({ :DRIVER => driver }) unless driver.blank?
			result.merge!({ :TASK => app_name }) unless app_name.blank?
			result.merge!({ :SERVICE => service }) unless service.blank?

			attributes = {}
			node.elements.each('//Attributes//Attribute') do |dsn_attribute|
				attributes.merge! ({
					:A_NAME => dsn_attribute.attributes['name'],
					:A_VALUE => dsn_attribute.attributes['value']
				})
			end

			result.merge!({ :ATTRIBUTES => attributes }) unless attributes.empty?

			results << result
		end

		return results
	end

	# Decrypts passwords using Microsoft's published key:
	# http://msdn.microsoft.com/en-us/library/cc422924.aspx
	def self.decrypt(encrypted_data)
		pass = ""
		padding = "=" * (4 - (encrypted_data.length % 4))
		epassword = "#{encrypted_data}#{padding}"
		decoded = Rex::Text.decode_base64(epassword)

		key = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
		aes = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
		begin
			aes.decrypt
			aes.key = key
			plaintext = aes.update(decoded)
			plaintext << aes.final
			pass = plaintext.unpack('v*').pack('C*') # UNICODE conversion
		rescue OpenSSL::Cipher::CipherError => e
			puts "Unable to decode: \"#{encrypted_data}\" Exception: #{e}"
		end

		return pass
	end

end
end
end

