class RenameAndPruneNessusVulns < ActiveRecord::Migration

	class Vuln < ActiveRecord::Base
	end

	# No table changes, just vuln renaming to drop the NSS id
	# from those vulns that have it and a descriptive name.
	def self.up
		Vuln.find(:all).each do |v|
			if v.name =~ /^NSS-0?\s*$/
				v.delete
				next
			end
			next unless(v.name =~ /^NSS-[0-9]+\s(.+)/)
			new_name = $1
			next if(new_name.nil? || new_name.strip.empty?)
			v.name = new_name
			v.save!
		end
	end

	def self.down
		say "Cannot un-rename and un-prune NSS vulns for migration 20110517160800."
	end

end
