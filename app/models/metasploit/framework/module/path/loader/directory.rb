# Concerns loading module from a directory
class Metasploit::Framework::Module::Path::Loader::Directory < Metasploit::Framework::Module::Path::Loader::Base
  # Returns true if the path is a directory
  #
  # @param (see Msf::Modules::Loader::Base#loadable?)
  # @return [true] if `module_path` is a directory.
  # @return [false] otherwise
  def loadable?(module_path)
    module_path.directory?
  end

  protected

  # Yields each `Metasploit::Model::Ancestor` in the module path that has
  # changed or all `Metasploit::Model::Ancestor` if `:force => true`.
  #
  # @param (see Metasploit::Framework::Module::Path::Loader::Base#each_module_ancestor)
  # @option (see Metasploit::Framework::Module::Path::Loader::Base#each_module_ancestor)
  # @yield (see Msf::Modules::Loader::Base#each_module_ancestor)
  # @yieldparam (see Msf::Modules::Loader::Base#each_module_ancestor)
  # @yieldreturn (see Msf::Modules::Loader::Base#each_module_ancestor)
  # @return (see Msf::Modules::Loader::Base#each_module_ancestor)
  def each_module_ancestor(module_path, options={})
    real_pathname = Pathname.new(module_path.real_path)

    real_pathname.each_child do |child_real_pathname|
      if child_real_pathname.directory?
        module_type_directory = child_real_pathname.basename
        module_type = Metasploit::Framework::Module::Ancestor::MODULE_TYPE_BY_DIRECTORY[module_type_directory]

        if module_type_enabled? module_type
          child_real_path = child_real_pathname.to_path

          Rex::Find.find(child_real_path) do |descendant_path|
            ancestor = module_path.module_ancestor_from_path(descendant_path, options)

            if ancestor
              yield ancestor
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