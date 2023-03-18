# -*- coding: binary -*-

module Msf::Auxiliary::ManageEngineXnode::Config
  CONFIG_FILE_DOES_NOT_EXIST = 1
  CANNOT_READ_CONFIG_FILE = 2
  DATA_TO_DUMP_EMPTY = 3
  DATA_TO_DUMP_WRONG_FORMAT = 4

  # Reads the configuration file for the current ManageEngine Xnode module in order to obtain the data repositories (tables) and fields (columns) to dump.
  #
  # @param config_file [String] String containing the full path to the configuration file to read.
  # @return [Hash, Integer] Hash containing the data repositories (tables) and their fields (columns) to dump if reading the config file succeeded, error code otherwise
  def grab_config(config_file)
    # get the specified data repositories (tables) and fields (columns) to dump from the config file
    return CONFIG_FILE_DOES_NOT_EXIST unless File.exist?(config_file)

    begin
      config_contents = File.read(config_file)
      data_to_dump = YAML.safe_load((config_contents))
    rescue StandardError => e
      print_error("Encountered the following error while trying to load #{config_file}:")
      print_error(e.to_s)
      return CANNOT_READ_CONFIG_FILE
    end

    return DATA_TO_DUMP_EMPTY if data_to_dump.empty?

    return DATA_TO_DUMP_WRONG_FORMAT unless data_to_dump.instance_of?(Hash)

    data_to_dump
  end

  # Returns an array of data repositories that may exist in ManageEngine Audit Plus
  #
  # @return [Array] list of possible data repositories in ManageEngine Audit Plus
  def ad_audit_plus_data_repos
    [
      'AdapFileAuditLog',
      'AdapPowershellAuditLog',
      'AdapSysMonAuditLog',
      'AdapDNSAuditLog',
      'AdapADReplicationAuditLog',
    ]
  end


  # Returns an array of data repositories that may exist in ManageEngine DataSecurity Plus
  #
  # @return [Array] list of possible data repositories in ManageEngine DataSecurity Plus
  def datasecurity_plus_data_repos
    [
      'DSPEmailAuditAttachments',
      'DSPEmailAuditReport',
      'DSPEndpointAuditReport',
      'DSPEndpointClassificationReport',
      'DSPEndpointIncidentReport',
      'DspEndpointPrinterAuditReport',
      'DspEndpointWebAuditReport',
      'DSPFileAnalysisAlerts',
      'RAAlertHistory',
      'RAIncidents',
      'RAViolationRecords',
    ]
  end

  # Returns the full module so that config_status::<status> can be used in the modules importing this library
  # as shorthand to access the error codes defined at the start of the module
  #
  # @return [Module] Msf::Auxiliary::ManageEngineXnode::Config
  def config_status
    Msf::Auxiliary::ManageEngineXnode::Config
  end
end
