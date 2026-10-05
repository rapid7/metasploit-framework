# frozen_string_literal: true
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Process

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OSX Security Product Enumeration',
        'Description' => %q{
          This module enumerates OSX systems for the presence of defensive products by enumerating the processes
          running on the device. The AV_FILE_LIST option specifies a file which contains a list of additional security
           products to hunt for, each of which should be seperated by a newline character.
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
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )

  )

    register_options(
      [
        OptString.new('AV_FILE_LIST',
                      [
                        false,
                        'File containing a list of AV products to hunt for. Each value should be seperated by a newline character and matching will be done in a case insensitive fashion', nil
                      ]),
      ]
    )
  end

  # good canidate for an acessory method
  # reads a file and returns each line as an element in an array
  def file_to_array(file)
    f = File.open file
    f.readlines.map(&:chomp)
  end

  def enum_processes(product)
    @processes.each do |process|
      # change capitalization on process name and our products so we don't have to deal with funky regexes
      name = process['name'].downcase

      next unless name.include?(product.downcase)

      print_good("Found potential process artifact for #{product}: #{process.inspect}")

      # following post/linux/gather/enum_protections.rb
      report_note(
        host: session,
        type: 'osx.protection',
        data: { "#{product}": process.inspect }, # need to test this
        update: :unique_data
      )
    end
  end

  def run
    products = [
      'LuLu', 'BlockBlock', 'DoNotDisturb', 'ReiKey', 'RansomWhere', 'OverSight', 'CrowdStrike',
      'Jamf', 'NetSkope', 'Qualys', 'BitDefender', 'Symantec'
    ]

    print_status('Retrieving process list...')
    @processes = get_processes

    print_status('Hunting processes for AV products...')

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
  end
end
