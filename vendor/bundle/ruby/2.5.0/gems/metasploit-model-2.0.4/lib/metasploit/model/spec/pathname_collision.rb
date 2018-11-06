# Error raised if a Pathname already exists on disk when one of the real_paths for metasploit-models factories
# is generated or derived, which would indicate that a prior spec did not clean up properly.
class Metasploit::Model::Spec::PathnameCollision < Metasploit::Model::Spec::Error
  # Checks if there is a pathname collision.
  #
  # @param (see #initialize)
  # @return [void]
  # @raise [Metasploit::Model::Spec::PathnameCollision] if `pathname.exist?` is `true`.
  def self.check!(pathname)
    if pathname.exist?
      raise new(pathname)
    end
  end

  # @param pathname [Pathname] Pathname that already exists on disk
  def initialize(pathname)
    super(
        "#{pathname} already exists.  " \
              "Metasploit::Model::Spec.remove_temporary_pathname was not called after the previous spec."
    )
  end
end
