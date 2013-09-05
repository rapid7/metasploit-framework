##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex'
require 'msf/core'
require 'msf/core/post/file'
require 'msf/core/post/windows/registry'
require 'yaml'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::File
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather File and Registry Artifacts Enumeration',
      'Description'   => %q{
        This module will check the file system and registry for particular artifacts. The
        list of artifacts is read from data/post/enum_artifacts_list.txt or a user specified file. Any
        matches are written to the loot. },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'averagesecurityguy <stephen[at]averagesecurityguy.info>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptPath.new( 'ARTIFACTS',
          [
            true,
            'Full path to artifacts file.',
            ::File.join(Msf::Config.data_directory, 'post', 'enum_artifacts_list.txt')
          ])
      ], self.class)
  end

  def run
    # Store any found artifacts so they can be written to loot
    evidence = {}

    # Load artifacts from yaml file. Artifacts are organized by what they
    # are evidence of.
    yaml = YAML::load_file(datastore['ARTIFACTS'])
    yaml.each_key do |key|
      print_status("Searching for artifacts of #{key}")
      files = yaml[key]['files']
      regs = yaml[key]['reg_entries']
      found = []

      # Process file entries
      vprint_status("Processing #{files.length.to_s} file entries for #{key}.")

      files.each do |file|
        digest = file_remote_digestmd5(file['name'])
        # if the file doesn't exist then digest will be nil
        next if digest == nil
        if digest == file['csum'] then found << file['name'] end
      end

      # Process registry entries
      vprint_status("Processing #{regs.length.to_s} registry entries for #{key}.")

      regs.each do |reg|
        rdata = registry_getvaldata(reg['key'], reg['val'])
        if rdata.to_s == reg['data']
          found << reg['key'] + '\\' + reg['val']
        end
      end

      # Did we find anything? If so store it in the evidence hash to be
      # saved in the loot.
      if found.empty?
        print_status("No artifacts of #{key} found.")
      else
        print_status("Artifacts of #{key} found.")
        evidence[key] = found
      end
    end

    save(evidence, "Enumerated Artifacts")
  end

  def save(data, name)
    str = ""
    data.each_pair do |key, val|
      str << "Evidence of #{key} found.\n"
      val.each do |v|
        str << "\t" + v + "\n"
      end
    end

    f = store_loot('enumerated.artifacts', 'text/plain', session, str, name)
    print_status("#{name} stored in: #{f}")
  end

end
