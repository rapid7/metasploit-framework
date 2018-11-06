module Nexpose

  class Connection

    # Retrieve a list of all backups currently stored on the Console.
    #
    # @return [Array[Backup]] List of backups.
    #
    def list_backups
      data = DataTable._get_dyn_table(self, '/data/admin/backups?tableID=BackupSynopsis')
      data.map { |b| Backup.parse(b) }
    end

    # Create a backup of this security console's data.
    # A restart will be initiated in order to put the product into maintenance
    # mode while the backup is made. It will then restart automatically.
    #
    # @param [Boolean] platform_independent Whether to make a platform
    #   independent backup.
    # @param [String] description A note about this backup which will be
    #   visible through the web interface.
    # @return [Boolean] Whether a backup is successfully initiated.
    #
    def backup(platform_independent = false, description = nil)
      parameters = { 'backup_desc' => description,
                     'cmd' => 'backup',
                     'platform_independent' => platform_independent,
                     'targetTask' => 'backupRestore' }
      xml = AJAX.form_post(self, '/admin/global/maintenance/maintCmd.txml', parameters)
      if !!(xml =~ /succeded="true"/)
        _maintenance_restart
      end
    end

    # Initiate database maintenance tasks to improve database performance and
    # consistency.
    # A restart will be initiated in order to put the product into maintenance
    # mode while the tasks are run. It will then restart automatically.
    #
    # @param [Boolean] clean_up Removes any unnecessary data from the database.
    # @param [Boolean] compress Compresses the database tables and reclaims
    #   unused, allocated space.
    # @param [Boolean] reindex Drops and recreates the database indexes for
    #   improved performance.
    # @return [Boolean] Whether a maintenance tasks are successfully initiated.
    #
    def db_maintenance(clean_up = false, compress = false, reindex = false)
      return unless compress || clean_up || reindex
      parameters = { 'cmd' => 'startMaintenance', 'targetTask' => 'dbMaintenance' }
      parameters['cleanup']  = 1 if clean_up
      parameters['compress'] = 1 if compress
      parameters['reindex']  = 1 if reindex
      xml = AJAX.form_post(self, '/admin/global/maintenance/maintCmd.txml', parameters)
      if !!(xml =~ /succeded="true"/)
        _maintenance_restart
      end
    end

    def _maintenance_restart
      parameters = { 'cancelAllTasks' => false,
                     'cmd' => 'restartServer',
                     'targetTask' => 'maintModeHandler' }
      xml = AJAX.form_post(self, '/admin/global/maintenance/maintCmd.txml', parameters)
      !!(xml =~ /succeded="true"/)
    end
  end

  # Details about an existing backup on the security console.
  #
  class Backup

    # Filename
    attr_reader :name
    # Date the backup was made.
    attr_reader :date
    # Description of the backup.
    attr_reader :description
    # Nexpose version the console was on when the backup was made.
    attr_reader :version
    # Whether the backup is platform-idependent or not.
    attr_reader :platform_independent
    # Size of backup file on disk, in Bytes. Can be used to estimate the amount
    # of time the backup may take to load.
    attr_reader :size

    def initialize(name, date, description, version, independent, size)
      @name                 = name
      @date                 = date
      @description          = description
      @version              = version
      @platform_independent = independent
      @size                 = size
    end

    # Restore this backup to the Nexpose console.
    # It will restart the console after acknowledging receiving the request.
    #
    # @param [Connection] nsc An active connection to a Nexpose console.
    # @param [String] (Optional) The password to use when restoring the backup.
    # @return [Boolean] Whether the request was received.
    #
    def restore(nsc, password = nil)
      raise 'Supplied Password is incorrect for restoring this Backup.' if invalid_backup_password?(nsc, password)
      parameters = { 'backupid' => @name,
                     'cmd' => 'restore',
                     'targetTask' => 'backupRestore',
                     'password' => password }
      xml = AJAX.form_post(nsc, '/admin/global/maintenance/maintCmd.txml', parameters)
      if !!(xml =~ /succeded="true"/)
        nsc._maintenance_restart
      end
    end

    # Remove this backup file from the security console.
    #
    # @param [Connection] nsc An active connection to a Nexpose console.
    # @return [Boolean] If the backup was removed.
    #
    def delete(nsc)
      parameters = { 'backupid' => @name,
                     'cmd' => 'deleteBackup',
                     'targetTask' => 'backupRestore' }
      xml = AJAX.form_post(nsc, '/admin/global/maintenance/maintCmd.txml', parameters)
      !!(xml =~ /succeded="true"/)
    end

    def self.parse(hash)
      new(hash['Download'],
          Time.at(hash['Date'].to_i / 1000),
          hash['Description'],
          hash['Version'],
          hash['Platform-Independent'],
          hash['Size'])
    end

    private

    def invalid_backup_password?(nsc, password)
      !correct_backup_password?(nsc, password) if backup_need_password?(nsc)
    end

    def backup_need_password?(nsc)
      resp = Nexpose::AJAX.get(nsc, '/data/admin/backups/password', Nexpose::AJAX::CONTENT_TYPE::JSON, 'backupID' => name)
      resp == 'true'
    end

    def correct_backup_password?(nsc, password)
      raise 'This Backup file requires a Password. Please include a password during the restore command.' if password.nil?
      resp = Nexpose::AJAX.post(nsc, "/data/admin/backups/password?backupID=#{name}&password=#{password}", nil, Nexpose::AJAX::CONTENT_TYPE::JSON)
      resp == 'true'
    end

  end
end
