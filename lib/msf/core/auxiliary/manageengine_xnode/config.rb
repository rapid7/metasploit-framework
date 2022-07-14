# -*- coding: binary -*-

module Msf::Auxiliary::ManageengineXnode::Config
  # Reads the configuration file for the current ManageEngine Xnode module in order to obtain the data repositories (tables) and fields (columns) to dump.
  #
  # @param config_file [String] String containing the full path to the configuration file to read.
  # @return [Hash, Integer] Hash containing the data repositories (tables) and their fields (columns) to dump if reading the config file succeeded, error code otherwise
  def grab_config(config_file)
    # get the specified data respositories (tables) and fields (columns) to dump from the config file
    return 1 unless File.exists? config_file

    begin
      data_to_dump = YAML.load_file((config_file))
    rescue StandardError => e
      print_error("Encountered the following error while trying to load #{config_file}:\n#{e.to_s}")
      return 2      
    end

    return 3 if data_to_dump.empty?

    return 4 unless data_to_dump.instance_of?(Hash)

    data_to_dump
  end

  # returns an array of data respositories that may exist in ManageEngine Audit Plus
  #
  # @return [Array] list of possible data respositories in ManageEngine Audit Plus
  def ad_audit_plus_data_repos
    [
      'AdapFileAuditLog',
      'AdapPowershellAuditLog',
      'AdapSysMonAuditLog',
      'AdapDNSAuditLog',
      'AdapADReplicationAuditLog',
    ]
  end


  # returns an array of data respositories that may exist in ManageEngine DataSecurity Plus
  #
  # @return [Array] list of possible data respositories in ManageEngine DataSecurity Plus
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
end
