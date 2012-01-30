module Msf
class DBManager

class Cred < ActiveRecord::Base
	include DBSave
	belongs_to :service

	KEY_ID_REGEX = /([0-9a-fA-F:]{47})/ # Could be more strict

	# Returns its workspace
	def workspace
		self.service.host.workspace
	end

	# Returns its key id. If this is not an ssh-type key, returns nil.
	def ssh_key_id
		return nil unless self.ptype =~ /^ssh_/
		return nil unless self.proof =~ KEY_ID_REGEX
		$1.downcase # Can't run into NilClass problems.
	end

	# Returns all private keys with matching key ids, including itself
	# If this is not an ssh-type key, always returns an empty array.
	def ssh_private_keys
		return [] unless self.ssh_key_id
		matches = self.class.all(:conditions => ["creds.ptype = ? AND creds.proof ILIKE ?", "ssh_key", "%#{self.ssh_key_id}%"])
		matches.select {|c| c.workspace == self.workspace}
	end

	# Returns all public keys with matching key ids, including itself
	# If this is not an ssh-type key, always returns an empty array.
	def ssh_public_keys
		return [] unless self.ssh_key_id
		matches = self.class.all(:conditions => ["creds.ptype = ? AND creds.proof ILIKE ?", "ssh_pubkey", "%#{self.ssh_key_id}%"])
		matches.select {|c| c.workspace == self.workspace}
	end

	# Returns all keys with matching key ids, including itself
	# If this is not an ssh-type key, always returns an empty array.
	def ssh_keys
		(self.ssh_private_keys | self.ssh_public_keys)
	end
	
	def ssh_key_matches?(other_cred)
		return false unless other_cred.kind_of? self.class
		return false unless self.ptype == other_cred.ptype
		case self.ptype
		when "ssh_key"
			matches = self.ssh_private_keys
		when "ssh_pubkey"
			matches = self.ssh_public_keys
		else
			false
		end
		matches.include?(self) and matches.include?(other_cred)
	end

end

end
end
