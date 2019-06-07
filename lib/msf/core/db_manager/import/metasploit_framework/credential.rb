module Msf::DBManager::Import::MetasploitFramework::Credential
  # Import credentials given a path to a valid manifest file
  #
  # @param creds_dump_manifest_path [String]
  # @param workspace [Mdm::Workspace] Default: {#workspace}
  # @return [void]
  def import_msf_cred_dump(creds_dump_manifest_path, workspace)
    manifest_file = File.open(creds_dump_manifest_path)
    origin = Metasploit::Credential::Origin::Import.create!(filename: File.basename(creds_dump_manifest_path))
    importer = Metasploit::Credential::Importer::Core.new(workspace: workspace, input: manifest_file, origin: origin)
    importer.import!
  end

  # Import credentials given a path to a valid manifest file
  #
  # @option args [String] :filename
  # @option args [Mdm::Workspace] :wspace Default: {#workspace}
  # @return [void]
  def import_msf_cred_dump_zip(args = {})
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    origin = Metasploit::Credential::Origin::Import.create!(filename: File.basename(args[:filename]))
    importer = Metasploit::Credential::Importer::Zip.new(workspace: wspace, input: File.open(args[:filename]), origin: origin)
    importer.import!
    nil
  end

  # Perform in an import of an msfpwdump file
  def import_msf_pwdump(args={}, &block)
    filename = File.basename(args[:data].path)
    wspace   = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    origin   = Metasploit::Credential::Origin::Import.create!(filename: filename)
    importer = Metasploit::Credential::Importer::Pwdump.new(input: args[:data], workspace: wspace, filename: filename, origin:origin)
    importer.import!
    importer.input.close unless importer.input.closed?
  end
end
