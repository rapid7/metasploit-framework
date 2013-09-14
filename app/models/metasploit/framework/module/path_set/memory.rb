# Set of {Metasploit::Framework::Module::Path in-memory module paths}.
class Metasploit::Framework::Module::PathSet::Memory < Metasploit::Framework::Module::PathSet::Base
  # Adds path to this set.
  #
  # @param (see Metasploit::Framework::Module::PathSet::Base)
  # @option (see Metasploit::Framework::Module::PathSet::Base)
  # @return [Metasploit::Framework::Module::Path]
  def add(real_path, options={})
    path = Metasploit::Framework::Module::Path.new(
        :gem => options[:gem],
        :name => options[:name],
        :real_path => real_path
    )
    path.valid!

    path.path_set = self

    added = add_path(path)

    added
  end

  # Maps (gem, name) tuples to their
  # {Metasploit::Framework::Module::Path paths}.
  # {Metasploit::Framework::Module::Path Paths} without a
  # {Metasploit::Framework::Module::Path#gem gem} are only stored in
  # {#path_by_real_path}.
  #
  # @return [Hash{String => Metasploit::Framework::Module::Path}]
  def path_by_name_by_gem
    @path_by_name_by_gem ||= Hash.new { |path_by_name_by_gem, gem|
      path_by_name = {}
      path_by_name_by_gem[gem] = path_by_name
    }
  end

  # Maps real paths to their {Metasploit::Framework::Module::Path
  # paths}.  Used to prevent real path collisions between
  # {Metasploit::Framework::Module::Path paths} with and without
  # {Metasploit::Framework::Module::Path#gem}.
  # {Metasploit::Framework::Module::Path} with a
  # {Metasploit::Framework::Module::Path#gem} is favored over a
  # {Metasploit::Framework::Module::Path} without a
  # {Metasploit::Framework::Module::Path#gem}.
  #
  # @return [Hash{String => Measploit::Framework::Module::Path}]
  def path_by_real_path
    @path_by_real_path ||= {}
  end
end
