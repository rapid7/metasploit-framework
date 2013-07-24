# Concerns loading module from a directory
class Msf::Modules::Loader::Directory < Msf::Modules::Loader::Base
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
  # @param [Array] modules An array of regex patterns to search for specific modules
  # @yield (see Msf::Modules::Loader::Base#each_module_reference_name)
  # @yieldparam [String] path The path to the directory.
  # @yieldparam [String] type The type correlated with the directory under path.
  # @yieldparam module_reference_name (see Msf::Modules::Loader::Base#each_module_reference_name)
  # @return (see Msf::Modules::Loader::Base#each_module_reference_name)
  def each_module_reference_name(path, opts={})
    whitelist = opts[:whitelist] || []
    ::Dir.foreach(path) do |entry|
      if entry.downcase == '.svn'
        next
      end

      full_entry_path = ::File.join(path, entry)
      type = entry.singularize

      unless ::File.directory?(full_entry_path) and
             module_manager.type_enabled? type
        next
      end

      full_entry_pathname = Pathname.new(full_entry_path)

      # Try to load modules from all the files in the supplied path
      Rex::Find.find(full_entry_path) do |entry_descendant_path|
        if module_path?(entry_descendant_path)
          entry_descendant_pathname = Pathname.new(entry_descendant_path)
          relative_entry_descendant_pathname = entry_descendant_pathname.relative_path_from(full_entry_pathname)
          relative_entry_descendant_path = relative_entry_descendant_pathname.to_s

          # The module_reference_name doesn't have a file extension
          module_reference_name = module_reference_name_from_path(relative_entry_descendant_path)

          # If the modules argument is set, this means we only want to load specific ones instead
          # of loading everything to memory - see msfcli.
          if whitelist.empty?
            # Load every module we see, which is the default behavior.
            yield path, type, module_reference_name
          else
              whitelist.each do |pattern|
              # We have to use entry_descendant_path to see if this is the module we want, because
              # this is easier to identify the module type just by looking at the file path.
              # For example, if module_reference_name is used (or a parsed relative path), you can't
              # really tell if php/generic is a NOP module, a payload, or an encoder.
              if entry_descendant_path =~ pattern
                yield path, type, module_reference_name
              else
                next
              end
            end
          end
        end
      end
    end
  end

  # Returns the full path to the module file on disk.
  #
  # @param (see Msf::Modules::Loader::Base#module_path)
  # @return [String] Path to module file on disk.
  def module_path(parent_path, type, module_reference_name)
    typed_path = self.typed_path(type, module_reference_name)
    full_path = File.join(parent_path, typed_path)

    full_path
  end

  # Loads the module content from the on disk file.
  #
  # @param (see Msf::Modules::Loader::Base#read_module_content)
  # @return (see Msf::Modules::Loader::Base#read_module_content)
  def read_module_content(parent_path, type, module_reference_name)
    full_path = module_path(parent_path, type, module_reference_name)

    module_content = ''

    begin
      # force to read in binary mode so Pro modules won't be truncated on Windows
      File.open(full_path, 'rb') do |f|
        # Pass the size of the file as it leads to faster reads due to fewer buffer resizes. Greatest effect on Windows.
        # @see http://www.ruby-forum.com/topic/209005
        # @see https://github.com/ruby/ruby/blob/ruby_1_8_7/io.c#L1205
        # @see https://github.com/ruby/ruby/blob/ruby_1_9_3/io.c#L2038
        module_content = f.read(f.stat.size)
      end
    rescue Errno::ENOENT => error
      load_error(full_path, error)
    end

    module_content
  end
end