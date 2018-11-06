class AddTemplatePrefs < ActiveRecord::Migration
	def self.up
		remove_column :email_templates, :generate_exe
		add_column :email_templates, :prefs, :text
		add_column :web_templates, :prefs, :text
	end
	def self.down
		remove_column :email_templates, :prefs
		remove_column :web_templates, :prefs
	end
end
