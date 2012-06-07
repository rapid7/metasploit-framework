class AddVulnDetails < ActiveRecord::Migration

	def self.up
		create_table :vuln_details do |t|
			t.integer   :vuln_id     # Vuln table reference
			t.float		:cvss_score  # 0.0 to 10.0
			t.string	:cvss_vector # Ex: (AV:N/AC:L/Au:N/C:C/I:C/A:C)(AV:N/AC:L/Au:N/C:C/I:C/A:C)

			t.string	:title       # Short identifier
			t.text		:description # Plain text or HTML (trusted)
			t.text		:solution    # Plain text or HTML (trusted)
			t.binary	:proof       # Should be UTF-8, but may not be, sanitize on output
						             # Technically this duplicates vuln.info, but that field
						             # is poorly managed / handled today. Eventually we will
						             # replace vuln.info

			# Nexpose-specific fields
			t.integer	:nx_console_id   # NexposeConsole table reference
			t.integer	:nx_device_id    # Reference from the Nexpose side
			t.string	:nx_vuln_id      # 'jre-java-update-flaw'
			t.float		:nx_severity     # 0-10
			t.float		:nx_pci_severity # 0-10
			t.timestamp	:nx_published    # Normalized from "20081205T000000000"
			t.timestamp	:nx_added        # Normalized from "20081205T000000000"
			t.timestamp	:nx_modified     # Normalized from "20081205T000000000"
			t.text		:nx_tags         # Comma separated
	
		end
	end

	def self.down
		drop_table :vuln_details
	end
end
