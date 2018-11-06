class AddGenerateExeColumn < ActiveRecord::Migration
	def self.up
		add_column :email_templates, :generate_exe, :boolean, :null => false, :default => false
	end
	def self.down
		remove_column :email_templates, :generate_exe
	end
end
