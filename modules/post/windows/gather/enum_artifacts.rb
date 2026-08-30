##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'yaml'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::File
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather File and Registry Artifacts Enumeration',
        'Description' => %q{
          This module will check the file system and registry for particular artifacts.

          The list of artifacts is read in YAML format from data/post/enum_artifacts_list.txt
          or a user specified file. Any matches are written to the loot.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'averagesecurityguy <stephen[at]averagesecurityguy.info>' ],
        'Platform' => [ 'win' ],
        'SessionTypes' => %w[shell powershell meterpreter],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options([
      OptPath.new(
        'ARTIFACTS',
        [
          true,
          'Full path to artifacts file.',
          ::File.join(Msf::Config.data_directory, 'post', 'enum_artifacts_list.txt')
        ]
      )
    ])
  end

  def run
    # Load artifacts from yaml file. Artifacts are organized by what they are evidence of.
    begin
      yaml = YAML.load_file(datastore['ARTIFACTS'])
      raise 'File is not valid YAML' unless yaml.instance_of?(Hash)
    rescue StandardError => e
      fail_with(Failure::BadConfig, "Could not load artifacts YAML file '#{datastore['ARTIFACTS']}' : #{e.message}")
    end

    loot_data = ''

    yaml.each_key do |key|
      print_status("Searching for artifacts of #{key}")
      artifacts = []

      # Process file entries
      files = yaml[key]['files']
      vprint_status("Processing #{files.length} file entries for #{key} ...")

      files.each do |file|
        fname = file['name']
        csum = file['csum']

        digest = file_remote_digestmd5(fname)
        if digest == csum
          artifacts << fname
        end
      end

      # Process registry entries
      regs = yaml[key]['reg_entries']
      vprint_status("Processing #{regs.length} registry entries for #{key} ...")

      regs.each do |reg|
        k = reg['key']
        v = reg['val']
        rdata = registry_getvaldata(k, v)
        if rdata.to_s == reg['data']
          artifacts << "#{k}\\#{v}"
        end
      end

      # Process matches
      if artifacts.empty?
        print_status("No artifacts of #{key} found.")
        next
      end

      print_status("Artifacts of #{key} found.")
      loot_data << "Evidence of #{key} found.\n"
      loot_data << artifacts.map { |a| "\t#{a}\n" }.join
    end

    return if loot_data.blank?

    vprint_line(loot_data)

    loot_name = 'Enumerated Artifacts'
    f = store_loot(
      loot_name.downcase.split.join('.'),
      'text/plain',
      session,
      loot_data,
      loot_name
    )
    print_good("#{loot_name} stored in: #{f}")
  end
end
