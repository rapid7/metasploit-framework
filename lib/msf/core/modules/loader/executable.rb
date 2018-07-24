# -*- coding: binary -*-

require 'msf/core/modules/loader'
require 'msf/core/modules/loader/base'
require 'msf/core/modules/external/shim'

# Concerns loading executables from a directory as modules
class Msf::Modules::Loader::Executable < Msf::Modules::Loader::Base
  # Returns true if the path is a directory
  #
  # @param (see Msf::Modules::Loader::Base#loadable?)
  # @return [true] if path is a directory
  # @return [false] otherwise
  def loadable?(path)
    File.directory?(path)
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

      unless ::File.directory?(full_entry_path) && module_manager.type_enabled?(type)
        next
      end

      full_entry_pathname = Pathname.new(full_entry_path)

      # Try to load modules from all the files in the supplied path
      Rex::Find.find(full_entry_path) do |entry_descendant_path|
        # Assume that all modules are scripts for now, workaround
        # filesystems where all files are labeled as executable.
        if script_path?(entry_descendant_path)
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
    begin
      content = Msf::Modules::External::Shim.generate(full_path, @module_manager.framework)
      if content
        return content
      else
        elog "Unable to load module #{full_path}, unknown module type"
        return ''
      end
    rescue ::Exception => e
      elog "Unable to load module #{full_path} #{e.class} #{e} #{e.backtrace.join "\n"}"
      # XXX migrate this to a full load_error when we can tell the user why the
      # module did not load and/or how to resolve it.
      # load_error(full_path, e)
      ''
    end
  end
end
