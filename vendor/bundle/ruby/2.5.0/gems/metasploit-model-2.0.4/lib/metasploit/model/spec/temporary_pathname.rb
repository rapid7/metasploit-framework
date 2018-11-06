# @example Temporary pathname creation and removal
#
#   # spec/spec_helper.rb
#   RSpec.config do |config|
#     config.before(:suite) do
#       Metasploit::Model::Spec.temporary_pathname = MyApp.root.join('spec', 'tmp')
#       # Clean up any left over files from a previously aborted suite
#       Metasploit::Model::Spec.remove_temporary_pathname
#     end
#
#     config.after(:each) do
#       Metasploit::Model::Spec.remove_temporary_pathname
#     end
#   end
module Metasploit::Model::Spec::TemporaryPathname
  # Removes {#temporary_pathname} from disk if it's been set and exists on disk.
  #
  # @return [void]
  def remove_temporary_pathname
    begin
      removal_pathname = temporary_pathname
    rescue Metasploit::Model::Spec::Error
      removal_pathname = nil
    end

    if removal_pathname and removal_pathname.exist?
      removal_pathname.rmtree
    end
  end

  # Pathname to hold temporary files for metasploit-model factories and sequence.  The directory must be be
  # safely writable and removable for specs that need to use the file system.
  #
  # @return [Pathname]
  # @raise [Metasploit::Model::Spec::Error] if {#temporary_pathname} is not set prior to calling this method.
  def temporary_pathname
    unless instance_variable_defined?(:@temporary_pathname)
      raise Metasploit::Model::Spec::Error, 'Metasploit::Model::Spec.temporary_pathname not set prior to use'
    end

    @temporary_pathname
  end

  # Sets the pathname to use for temporary directories and files used in metasploit_data_models factories and
  # sequences.
  #
  # @param pathname [Pathname] path to a directory.  It does not need to exist, but need to be in a writable parent
  #   directory so it can be removed by {#remove_temporary_pathname}.
  # @return [Pathname] `pathname`
  def temporary_pathname=(pathname)
    @temporary_pathname = pathname
  end
end
