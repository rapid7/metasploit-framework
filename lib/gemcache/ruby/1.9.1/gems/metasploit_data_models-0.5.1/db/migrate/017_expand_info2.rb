class ExpandInfo2 < ActiveRecord::Migration
	def self.up
		remove_column :events, :info
		change_table :events do |t|
			t.string    :info, :limit => 65536
		end

		remove_column :notes, :data
		change_table :notes do |t|
			t.string    :data, :limit => 65536
		end

		remove_column :vulns, :data
		change_table :vulns do |t|
			t.string    :data, :limit => 65536
		end

		remove_column :hosts, :info
		change_table :hosts do |t|
			t.string    :info, :limit => 65536
		end

		remove_column :services, :info
		change_table :services do |t|
			t.string    :info, :limit => 65536
		end
	end

	def self.down

		remove_column :events, :info
		change_table :events do |t|
			t.string    :info
		end

		remove_column :notes, :data
		change_table :notes do |t|
			t.string    :data, :limit => 4096
		end

		remove_column :hosts, :info
		change_table :hosts do |t|
			t.string    :info, :limit => 4096
		end

		remove_column :vulns, :data
		change_table :vulns do |t|
			t.string    :data, :limit => 4096
		end

		remove_column :services, :info
		change_table :services do |t|
			t.string    :info, :limit => 4096
		end

	end
end

