class FixWebTables < ActiveRecord::Migration
	
	def self.up
		change_column :web_pages, :path, :text
		change_column :web_pages, :query, :text
		change_column :web_pages, :cookie, :text
		change_column :web_pages, :auth, :text
		change_column :web_pages, :ctype, :text
		change_column :web_pages, :location, :text
		change_column :web_pages, :path, :text
		change_column :web_vulns, :path, :text
		change_column :web_vulns, :pname, :text
		
		add_column :web_pages, :request, :text
		add_column :web_vulns, :request, :text				
	end
	
	def self.down
		change_column :web_pages, :path, :text
		change_column :web_pages, :query, :text
		change_column :web_pages, :cookie, :text
		change_column :web_pages, :auth, :text
		change_column :web_pages, :ctype, :text
		change_column :web_pages, :location, :text
		change_column :web_pages, :path, :text
		change_column :web_vulns, :path, :text
		change_column :web_vulns, :pname, :text
		
		remove_column :web_pages, :request
		remove_column :web_vulns, :request
	end
end


