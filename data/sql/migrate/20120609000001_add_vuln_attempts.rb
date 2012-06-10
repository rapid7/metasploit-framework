class AddVulnAttempts < ActiveRecord::Migration

	def self.up
		create_table :vuln_attempts do |t|
			t.integer		:vuln_id       # Vuln table reference
			t.timestamp		:attempted_at  # Timestamp of when the session was opened or the module exited
			t.boolean		:exploited     # Whether or not the attempt succeeded
			t.string		:fail_reason   # Short string corresponding to a Msf::Exploit::Failure constant
			t.string		:username      # The user that tested this vulnerability
			t.text			:module        # The specific module name that was used
			t.integer		:session_id    # Database identifier of any opened session
			t.integer		:loot_id       # Database identifier of any 'proof' loot (for non-session exploits)
		end
	end

	def self.down
		drop_table :vuln_attempts
	end
end
