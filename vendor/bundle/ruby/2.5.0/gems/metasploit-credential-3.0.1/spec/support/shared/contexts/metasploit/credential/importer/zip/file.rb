RSpec.shared_context 'metasploit_credential_importer_zip_file' do
  #
  # Methods
  #

  def remove_metasploit_credential_importer_zip_files
    # Using POSIX filepath here b/c we don't care about RSpec on Windows
    Dir.glob("/tmp/metasploit_credential_importer_zip_file*") do |path|
      FileUtils.rm_rf(path)
    end
  end

  #
  # Callbacks
  #

  # Clean up leftovers from aborted spec runs.
  before(:example) do
    remove_metasploit_credential_importer_zip_files
  end

  # Clean up after completed spec runs.
  after(:example) do
    remove_metasploit_credential_importer_zip_files
  end
end