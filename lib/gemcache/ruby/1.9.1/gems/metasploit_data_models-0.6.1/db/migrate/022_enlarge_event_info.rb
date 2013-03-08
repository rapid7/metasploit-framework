class EnlargeEventInfo < ActiveRecord::Migration
	def self.up
		change_column :events, :info, :text
	end

	def self.down
		change_column :events, :info, :string, :limit => 65535
	end
end

