class AddSessionTable < ActiveRecord::Migration

	class Event < ActiveRecord::Base
		serialize :info
	end

	class SessionEvent < ActiveRecord::Base
		belongs_to :session
	end

	class Session < ActiveRecord::Base
		has_many :events, :class_name => 'AddSessionTable::SessionEvent'
		serialize :datastore
	end

	def self.up

 		create_table :sessions do |t|
 			t.integer :host_id

 			t.string  :stype       # session type: meterpreter, shell, etc
 			t.string  :via_exploit # module name 
 			t.string  :via_payload # payload name
 			t.string  :desc        # session description
 			t.integer :port
 			t.string  :platform    # platform type of the remote system
 			t.string  :routes

 			t.text    :datastore   # module's datastore

 			t.timestamp :opened_at, :null => false
 			t.timestamp :closed_at

 			t.string :close_reason
 		end

 		create_table :session_events do |t|
 			t.integer :session_id

 			t.string  :etype # event type: command, output, upload, download, filedelete
 			t.binary  :command
 			t.binary  :output
 			t.string  :remote_path
 			t.string  :local_path

 			t.timestamp :created_at
 		end

 		#
 		# Migrate session data from events table
 		#

 		close_events = Event.find_all_by_name("session_close")
 		open_events  = Event.find_all_by_name("session_open")

 		command_events  = Event.find_all_by_name("session_command")
 		output_events   = Event.find_all_by_name("session_output")
 		upload_events   = Event.find_all_by_name("session_upload")
 		download_events = Event.find_all_by_name("session_download")

 		open_events.each do |o|
 			c = close_events.find { |e| e.info[:session_uuid] == o.info[:session_uuid] }

 			s = Session.new(
 				:host_id => o.host_id,
 				:stype => o.info[:session_type],
 				:via_exploit => o.info[:via_exploit],
 				:via_payload => o.info[:via_payload],
 				:datastore => o.info[:datastore],
 				:opened_at => o.created_at
 			)

			if c
	 			s.closed_at = c.created_at
 				s.desc = c.info[:session_info]
 			else
 				# couldn't find the corresponding close event
 				s.closed_at = s.opened_at
 				s.desc = "?"
 			end

 			uuid = o.info[:session_uuid]

 			command_events.select { |e| e.info[:session_uuid] == uuid }.each do |e|
 				s.events.build(:created_at => e.created_at, :etype => "command", :command => e.info[:command] )
 			end

 			output_events.select { |e| e.info[:session_uuid] == uuid }.each do |e|
 				s.events.build(:created_at => e.created_at, :etype => "output", :output => e.info[:output] )
 			end

 			upload_events.select { |e| e.info[:session_uuid] == uuid }.each do |e|
 				s.events.build(:created_at => e.created_at, :etype => "upload", :local_path => e.info[:local_path], :remote_path  => e.info[:remote_path] )
 			end

 			download_events.select { |e| e.info[:session_uuid] == uuid }.each do |e|
 				s.events.build(:created_at => e.created_at, :etype => "download", :local_path => e.info[:local_path], :remote_path  => e.info[:remote_path] )
 			end

 			s.events.sort_by(&:created_at)

 			s.save!
 		end
	end

	def self.down
		drop_table :sessions
		drop_table :session_events
	end
end
