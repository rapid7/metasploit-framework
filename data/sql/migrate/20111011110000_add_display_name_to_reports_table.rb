class AddDisplayNameToReportsTable < ActiveRecord::Migration

	class Report < ActiveRecord::Base
	end

	def self.up

		add_column :reports, :name, :string, :limit => 63

		# Migrate to have a default name.
		
		Report.find(:all).each do |report|
			rtype = report.rtype.to_s =~ /^([A-Z0-9]+)\x2d/i ? $1 : "AUDIT"
			default_name = rtype[0,57].downcase.capitalize + "-" + report.id.to_s[0,5]
			report.name = default_name
			report.save
		end
	end

	def self.down
		remove_column :reports, :name
	end

end
