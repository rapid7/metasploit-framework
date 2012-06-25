class AddExploitAttempts < ActiveRecord::Migration

	def self.up
		create_table :exploit_attempts do |t|
			t.integer		:host_id       # Host table reference (primary)
			t.integer		:service_id    # Service table reference (optional)
			t.integer		:vuln_id       # Vuln table reference (optional)
			t.timestamp		:attempted_at  # Timestamp of when the session was opened or the module exited
			t.boolean		:exploited     # Whether or not the attempt succeeded
			t.string		:fail_reason   # Short string corresponding to a Msf::Exploit::Failure constant
			t.string		:username      # The user that tested this vulnerability
			t.text			:module        # The specific module name that was used
			t.integer		:session_id    # Database identifier of any opened session
			t.integer		:loot_id       # Database identifier of any 'proof' loot (for non-session exploits)
			t.integer       :port          # Port     -> Services are created/destroyed frequently and failed
			t.string        :proto         # Protocol |  attempts may be against closed ports.
		end

		add_column :hosts, :exploit_attempt_count, :integer, :default => 0
	end

	def self.down
		drop_table :exploit_attempts
		remove_column :hosts, :exploit_attempt_count
	end
end
