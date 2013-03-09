class AddHostDetails < ActiveRecord::Migration

	def self.up
		create_table :host_details do |t|
			t.integer   :host_id     # Host table reference

			# Nexpose-specific fields
			t.integer	:nx_console_id   # NexposeConsole table reference
			t.integer	:nx_device_id    # Reference from the Nexpose side
		end
	end

	def self.down
		drop_table :host_details
	end
end
