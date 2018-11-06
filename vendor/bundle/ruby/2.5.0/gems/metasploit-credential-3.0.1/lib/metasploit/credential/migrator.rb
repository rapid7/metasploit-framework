# This class provides migration behavior for converting `Mdm::Cred` objects to their appropriate counterparts in the
# {Metasploit::Credential} namespace.

class Metasploit::Credential::Migrator
  include Metasploit::Credential::Creation

  # @!attribute origin
  #   An origin for tracking how these credentials made it into the system.
  #   Treating this as an Import since there is no migration origin.
  #
  #
  #   @return [Metasploit::Credential::Origin::Import]
  attr_accessor :origin

  # @!attribute workspaces
  #   Where the migrated creds will originate
  #
  #
  #   @return [Array<Mdm::Workspace>]
  attr_accessor :workspaces


  # Sets up a migrator object with either a single workspace or all workspaces
  # @param [Mdm::Workspace] the workspace to act on
  # @return [void]
  def initialize(workspace=nil)
    @origin = Metasploit::Credential::Origin::Import.new(filename: 'MIGRATION')

    if workspace.present?
      @workspaces = [workspace]
    else
      @workspaces = Mdm::Workspace.all
    end
  end

  # Returns true if {#workspaces} contains `Mdm::Cred` objects
  # @return [Boolean]
  def creds_exist?
    workspaces.map(&:creds).flatten.present?
  end

  # Perform the migration
  # @return [void]
  def migrate!
    if creds_exist?
      Metasploit::Credential::Core.transaction do
        origin.save # we are going to use the one we instantiated earlier, since there is work to be done
        workspaces.each do |workspace|
          convert_creds_in_workspace(workspace)
        end
      end
    end
  end

  # Converts the `Mdm::Cred` objects in a single `Mdm::Workspace`
  # @param [Mdm::Workspace] the workspace to act on
  # @return [void]
  def convert_creds_in_workspace(workspace)
    workspace.creds.each do |cred|
      service = cred.service
      begin
        core = create_credential(
          origin: origin,
          private_data: private_data_from_cred(cred),
          private_type: cred_type_to_credential_class(cred.ptype),
          username: cred.user,
          workspace_id: workspace.id
        )
      rescue ActiveRecord::RecordInvalid => e
        logger = Metasploit::Credential::Core.logger

        logger.error("#{__method__} - Failed to migrate: #{cred.user}, Mdm::Cred id #{cred.id}")
        logger.error("#{__method__} -    validation errors: #{e}")
        logger.error("#{__method__} -    failing record: #{e.record.inspect}")
      else
        create_credential_login(
          address: service.host.address,
          core: core,
          port: service.port,
          protocol: service.proto,
          service_name: service.name,
          status: Metasploit::Model::Login::Status::UNTRIED,
          workspace_id: workspace.id
        )
      end
    end
  end


  # Converts types in the legacy credentials model to a type in the new one.
  # Assumes that anything that isn't 'smb_hash' but contains 'hash' will be a
  # NonreplaybleHash.
  # @param cred_type [String] the value from the ptype field of `Mdm::Cred`
  # @return[Symbol]
  def cred_type_to_credential_class(cred_type)
    return :ntlm_hash if cred_type == "smb_hash"
    return :ssh_key if cred_type == "ssh_key"
    return :nonreplayable_hash if cred_type.include? "hash"
    return :password
  end

  # Returns the text of the SSH key as read from the file
  # @param path [String] Path to an SSH key file on disk
  # @return [String]
  def key_data_from_file(path)
    # Sometimes we will set the :pass attribute to a file path containing the key
    if File.exist?(path)
      File.read(path)
    # In other cases we store the entire SSH key directly in the :pass attribute
    elsif Metasploit::Credential::SSHKey.new(data: path).private?
      path
    end
  end

  # Returns private data given an `Mdm::Cred`
  # @param cred [Mdm::Cred]
  # @return[String]
  def private_data_from_cred(cred)
    case cred.ptype
    when 'ssh_key'
      key_data_from_file(cred.pass)
    else
      cred.pass
    end
  end

end
