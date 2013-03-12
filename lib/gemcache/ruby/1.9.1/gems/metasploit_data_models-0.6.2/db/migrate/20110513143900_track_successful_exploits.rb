class TrackSuccessfulExploits < ActiveRecord::Migration


	class ExploitedHost < ActiveRecord::Base
	end

	class Vuln < ActiveRecord::Base
	end

	def self.up
		add_column :vulns, :exploited_at, :timestamp

		# Migrate existing exploited_hosts entries

		ExploitedHost.find(:all).select {|x| x.name}.each do |exploited_host|
			next unless(exploited_host.name =~ /^(exploit|auxiliary)\//)
			vulns = Vuln.find_all_by_name_and_host_id(exploited_host.name, exploited_host.host_id)
			next if vulns.empty?
			vulns.each do |vuln|
				vuln.exploited_at = exploited_host.updated_at
				vuln.save
			end
		end
		
	end

	def self.down
		remove_column :vulns, :exploited_at
	end

end
