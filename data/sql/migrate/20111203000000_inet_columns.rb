class InetColumns < ActiveRecord::Migration

	def self.up
		change_column :hosts, :address, :inet
		drop_column :hosts, :address6
	end

	def self.down
		change_column :hosts, :address, :text
		add_column :hosts, :address6, :text
	end

end
