class StandardizeInfoAndData < ActiveRecord::Migration
	def self.up
		# Remove the host requirement.  We'll add the column back in below.
		remove_column :vulns, :data
		change_table :vulns do |t|
			t.string :info, :limit => 65536
		end
	end

	def self.down
		remove_column :vulns, :info
		change_table :notes do |t|
			t.string :data, :limit => 65536

		end
	end
end

