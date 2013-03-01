class AddFailMessage < ActiveRecord::Migration

	def self.up
		add_column :vuln_attempts, :fail_detail, :text
		add_column :exploit_attempts, :fail_detail, :text
	end

	def self.down
		remove_column :vuln_attempts, :fail_detail
		remove_column :exploit_attempts, :fail_detail
	end
end
