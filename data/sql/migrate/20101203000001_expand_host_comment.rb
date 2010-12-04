class ExpandHostComment < ActiveRecord::Migration
	
	def self.up
		change_column :hosts, :comments, :text
	end
	
	def self.down
		change_column :hosts, :comments, :string, :limit => 4096
	end
end


