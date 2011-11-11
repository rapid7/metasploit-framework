class MoveOldImportedCredsToNewFiles < ActiveRecord::Migration

	class ImportedCred < ActiveRecord::Base
	end

	class CredFile < ActiveRecord::Base
	end

	class Workspace < ActiveRecord::Base
	end

	class << self

		def find_or_create_cred_path
			cred_files_dir = nil
			msf_base = Msf::Config.install_root
			pro_base = File.expand_path(File.join(msf_base, "..", "engine", "lib", "pro"))
			if File.directory? pro_base
				cred_files_dir = File.expand_path(File.join(msf_base, "..", "cred_files"))
				FileUtils.mkdir_p(cred_files_dir) unless File.exists?(cred_files_dir)
				if File.directory?(cred_files_dir) and File.writable?(cred_files_dir)
				end
			end
			return cred_files_dir
		end

		def find_all_imported_creds_by_workspace
			valid_ptypes = ["smb_hash", "userpass", "password"]
			valid_workspaces = Workspace.all.map {|w| w.id}
			creds = {}
			ImportedCred.all.each do |cred|
				next unless cred.ptype
				next unless valid_ptypes.include? cred.ptype
				next unless cred.workspace_id
				next unless valid_workspaces.include? cred.workspace_id
				creds[cred.workspace_id] ||= []
				creds[cred.workspace_id] << cred
			end
			return creds
		end

		def sort_creds_into_file_types(old_creds)
			files = {}
			old_creds.each do |wid,creds|
				filedata = {}
				creds.each do |cred|
					filedata[cred.ptype] ||= []
					case cred.ptype
					when "smb_hash", "userpass"
						filedata[cred.ptype] << ("%s %s" % [cred.user,cred.pass])
					when "password"
						filedata[cred.ptype] << cred.pass.to_s
					end
					files[wid] = filedata 
				end
			end
			return files
		end

		def write_creds_to_files(old_creds,cred_path)
			file_data_to_write = sort_creds_into_file_types(old_creds)
			files_written = []
			file_data_to_write.each do |wid, fdata_hash|
				fdata_hash.each do |ftype,cred_data|
					next unless cred_data
					next if cred_data.empty?
					fname = File.join(cred_path,"creds_#{wid}_#{ftype}-#{Time.now.utc.to_i}.txt")
					fdata = cred_data.join("\n")
					fh = File.open(fname, "wb")
					begin
						fh.write fdata
						fh.flush
					ensure
						fh.close 
					end
					files_written << fname
				end
			end
			return files_written
		end

		def register_new_files(new_files)
			successful_count = 0
			new_files.each do |fname|
				next unless File.split(fname).last =~ /^creds_([0-9]+)_(userpass|password|smb_hash)\-[0-9]+\.txt$/
				wid = $1
				next unless Workspace.find(wid)
				ftype = $2
				actual_ftype = case ftype
					when "smb_hash", "userpass"
						"userpass" # They're treated the same
					when "password"
						"pass"
					end
				next unless actual_ftype
				say "Registering credential file '%s' for workspace %d as type '%s'" % [fname,wid,actual_ftype]
				cred_file = CredFile.new
				cred_file.workspace_id = wid
				cred_file.created_by = ""
				cred_file.path = fname
				cred_file.name = "#{ftype}.txt"
				cred_file.desc = "Migrated #{ftype} credentials"
				cred_file.ftype = actual_ftype
				if cred_file.save
					successful_count += 1
					say "Successfully imported #{ftype} credentials for workspace #{wid}"
				end
			end
			successful_count
		end

	end

	def self.up
		cred_path = find_or_create_cred_path
		if cred_path
			old_imported_creds = find_all_imported_creds_by_workspace
			new_files = write_creds_to_files(old_imported_creds,cred_path)
			successful_count = register_new_files(new_files)
		end
	end

	# Sorry, can't get the old data back.
	def self.down
	end

end
