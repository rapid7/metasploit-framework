##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Wordpress Scanner',
      'Description' => 'Detects Wordpress Versions, Themes, and Plugins',
      'Author' => [
        'Christian Mehlmauer', # original module
        'h00die' # plugins and themes
      ],
      'License' => MSF_LICENSE
    )
    register_options [
      OptBool.new('EXPLOITABLE', [false, 'Only scan plugins and themes which a MSF module exists for', true]),
      OptPath.new('EXPLOITABLE_THEMES', [
        true, 'File containing exploitable by MSF themes',
        File.join(Msf::Config.data_directory, 'wordlists', 'wp-exploitable-themes.txt')
      ]),
      OptPath.new('EXPLOITABLE_PLUGINS', [
        true, 'File containing exploitable by MSF plugins',
        File.join(Msf::Config.data_directory, 'wordlists', 'wp-exploitable-plugins.txt')
      ]),
      OptBool.new('THEMES', [false, 'Detect themes', true]),
      OptBool.new('PLUGINS', [false, 'Detect plugins', true]),
      OptPath.new('THEMES_FILE', [
        true, 'File containing themes to enumerate',
        File.join(Msf::Config.data_directory, 'wordlists', 'wp-themes.txt')
      ]),
      OptPath.new('PLUGINS_FILE', [
        true, 'File containing plugins to enumerate',
        File.join(Msf::Config.data_directory, 'wordlists', 'wp-plugins.txt')
      ]),
      OptInt.new('PROGRESS', [true, 'how often to print progress', 1000])
    ]
  end

  def print_progress(host, i, total)
    print_status("#{host} - Progress #{i.to_s.rjust(Math.log10(total).ceil + 1)}/#{total} (#{((i.to_f / total) * 100).truncate(2)}%)")
  end

  def run_host(target_host)
    print_status("Trying #{target_host}")
    if wordpress_and_online?
      version = wordpress_version
      version_string = version || '(no version detected)'
      print_good("#{target_host} - Detected Wordpress #{version_string}")
      report_note(
        {
          host: target_host,
          proto: 'tcp',
          sname: (ssl ? 'https' : 'http'),
          port: rport,
          type: "Wordpress #{version_string}",
          data: target_uri.to_s
        }
      )
      if datastore['THEMES']
        print_status("#{target_host} - Enumerating Themes")

        if datastore['EXPLOITABLE']
          f = File.open(datastore['EXPLOITABLE_THEMES'], 'rb')
        else
          f = File.open(datastore['THEMES_FILE'], 'rb')
        end
        total = f.lines.count
        f.rewind
        f = f.lines
        f.each_with_index do |theme, i|
          theme = theme.strip
          print_progress(target_host, i, total) if i % datastore['PROGRESS'] == 0
          vprint_status("#{target_host} - Checking theme: #{theme}")
          version = check_theme_version_from_readme(theme)
          next if version == Msf::Exploit::CheckCode::Unknown # aka not found

          print_good("#{target_host} - Detected theme: #{theme} version #{version.details[:version]}")
          report_note(
            {
              host: target_host,
              proto: 'tcp',
              sname: (ssl ? 'https' : 'http'),
              port: rport,
              type: "Wordpress Theme: #{theme} version #{version.details[:version]}"
              # data: target_uri
            }
          )
        end
        print_status("#{target_host} - Finished scanning themes")
      end
      if datastore['PLUGINS']
        print_status("#{target_host} - Enumerating plugins")

        if datastore['EXPLOITABLE']
          f = File.open(datastore['EXPLOITABLE_PLUGINS'], 'rb')
        else
          f = File.open(datastore['PLUGINS_FILE'], 'rb')
        end
        total = f.lines.count
        f.rewind
        f = f.lines
        f.each_with_index do |plugin, i|
          plugin = plugin.strip
          print_progress(target_host, i, total) if i % datastore['PROGRESS'] == 0
          vprint_status("#{target_host} - Checking plugin: #{plugin}")
          version = check_plugin_version_from_readme(plugin)
          next if version == Msf::Exploit::CheckCode::Unknown # aka not found

          print_good("#{target_host} - Detected plugin: #{plugin} version #{version.details[:version]}")
          report_note(
            {
              host: target_host,
              proto: 'tcp',
              sname: (ssl ? 'https' : 'http'),
              port: rport,
              type: "Wordpress Plugin: #{plugin} version #{version.details[:version]}"
              # data: target_uri
            }
          )
        end
        print_status("#{target_host} - Finished scanning plugins")
      end
      print_status("#{target_host} - Finished all scans")
    end
  end
end
