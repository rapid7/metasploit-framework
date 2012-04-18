class MigrateCredData < ActiveRecord::Migration

	def self.up
		begin # Wrap the whole thing in a giant rescue.
		skipped_notes = []
		new_creds = []
		Mdm::Note.find(:all).each do |note|
			next unless note.ntype[/^auth\.(.*)/]
			service_name = $1
			if !service_name
				skipped_notes << note
				next
			end
			if note.host and note.host.respond_to?(:address)
				if note.service
					svc_id = note.service.id
				else
					candidate_services = []
					note.host.services.each do |service|
						if service.name == service_name
							candidate_services << service
						end
					end
					# Use the default port, or the first port that matches the protocol name.
					default_port = case service_name.downcase
						when 'ftp'; 21
						when /^smb/; 445
						when /^imap/; 143
						when 'telnet'; 23
						when 'pop3'; 110
						when 'http','domino','axis','wordpress','tomcat'; 80
						when 'tns'; 1521
						when 'snmp'; 161
						when 'mssql'; 1433
						when 'ssh'; 22
						when 'https'; 443
						when 'mysql'; 3306
						when 'db2'; 50000
						when 'postgres'; 5432
						else nil
					end
					if !default_port
						skipped_notes << note
						next
					end
					if candidate_services.size == 1
						svc_id = candidate_services.first.id
					elsif candidate_services.empty?
						Mdm::Service.new do |svc|
							svc.host_id = note.host.id
							svc.port = default_port
							svc.proto = 'tcp'
							svc.state = 'open'
							svc.name = service_name.downcase
							svc.save!
							svc_id = svc.id
						end
					elsif candidate_services.size > 1
						svc_ports = candidate_services.map{|s| s.port}
						if svc_ports.index(default_port)
							svc_id = candidate_services[svc_ports.index(default_port)].id
						else
							svc_id = candidate_services.first.id
						end
					end
				end
			else
				skipped_notes << note
				next
			end
			if note.data[:hash]
				ptype = 'smb_hash'
				pass = note.data[:hash]
			elsif note.data[:ssh_key]
				ptype = 'ssh_key'
				pass = note.data[:extra]
			else
				ptype = 'password'
				pass = note.data[:pass]
			end
			# Format domains and databases into the usernames.
			if note.ntype == "auth.smb_challenge"
				domain = note.data[:extra].match(/DOMAIN=([^\s]+)/)[1]
				if domain
					user = [domain, note.data[:user]].join("/")
				else
					user = note.data[:user]
				end
			elsif note.ntype =~ /auth\.(postgres|db2)/
				if note.data[:database]
					user = [note.data[:database], note.data[:user]].join("/")
				else
					user = note.data[:user]
				end
			else
				user = note.data[:user]
			end
			# Not actually a credentials, convert to migrated notes
			if service_name == 'smb' && note.data[:token]
				skipped_notes << note
				next
			end
			if service_name == 'tns' && note.data[:type] == "bruteforced_sid"
				skipped_notes << note
				next
			end
			# Special case for the bizarre reporting for aux/admin/oracle/oracle_login
			if service_name == 'tns' && note.data[:type] == "bruteforced_account"
				note.data[:data] =~ /([^\x2f]+)\x2f([^\s]+).*with sid (.*)/
				user = "#{$3}/#{$1}"
				pass = $2
			end
			new_creds << [svc_id, ptype, user, pass]
		end

		say "Migrating #{new_creds.size} credentials."
		new_creds.uniq.each do |note|
			Mdm::Cred.new do |cred|
				cred.service_id = note[0]
				cred.user = note[2]
				cred.pass = note[3]
				cred.ptype = note[1]
				cred.save!
			end
		end

		say "Migrating #{skipped_notes.size} notes."
		skipped_notes.uniq.each do |note|
			Mdm::Note.new do |new_note|
				new_note.host_id = note.host_id
				new_note.ntype = "migrated_auth"
				new_note.data = note.data.merge(:migrated_auth_type => note.ntype)
				new_note.save!
			end
		end

		say "Deleting migrated auth notes."
		Mdm::Note.find(:all).each do |note|
			next unless note.ntype[/^auth\.(.*)/]
			note.delete
		end
		rescue 
			say "There was a problem migrating auth credentials. Skipping."
			return true # Never fail!
		end
	end


	def self.down
		raise ActiveRecord::IrreversibleMigration
	end

end

