module Nexpose
  # Configuration structure for scheduled backups.
  class ScheduledBackup < APIObject
    require 'json'
    include JsonSerializer

    # Whether or not this schedule is enabled. Defaults to true if not set
    attr_accessor :enabled
    # Valid schedule types: daily, hourly, monthly-date, monthly-day, weekly.
    attr_accessor :schedule_type
    # The repeat interval based upon type.
    attr_accessor :schedule_interval
    # Starting time of the backup task (in unix epoch with milliseconds. Example: 1464956590000)
    attr_accessor :schedule_start
    # The description of the backup. Defaults to nil if not set
    attr_accessor :description
    # Whether the backup will be platform independent or not. Defaults to true if not set
    attr_accessor :platform_independent
    # Whether the backup should pause all local scans or wait for local scans to complete. Defaults to true if not set
    attr_accessor :pause_local_scans
    # Number of minutes to wait for running scans to pause/complete before aborting the backup task. Defaults to 0 if not set
    attr_accessor :cancellation_window

    def initialize(start:, enabled: true, type:, interval:, platform_independent: true, description: nil, pause_local_scans: true, cancellation_window: 0)
      @schedule_start       = start
      @enabled              = enabled
      @schedule_type        = type
      @schedule_interval    = interval.to_i
      @platform_independent = platform_independent
      @description          = description
      @pause_local_scans    = pause_local_scans
      @cancellation_window  = cancellation_window.to_i
    end

    def to_json
      JSON.generate(to_h)
    end

    def save(nsc)
      params = to_json
      AJAX.post(nsc, '/api/2.1/schedule_backup/', params, AJAX::CONTENT_TYPE::JSON)
    end

    def self.from_hash(hash)
      repeat_backup_hash = hash[:repeat_type]
      backup = new(start: hash[:start_date],
                   enabled: hash[:enabled],
                   type: repeat_backup_hash[:type],
                   interval: repeat_backup_hash[:interval],
                   platform_independent: hash[:platform_independent],
                   description: hash[:description],
                   pause_local_scans: hash[:pause_local_scans],
                   cancellation_window: hash[:cancellation_window])
      backup
    end

    def to_h
      backup_hash = {
        start_date: @schedule_start,
        enabled: @enabled,
        description: @description,
        platform_independent: @platform_independent,
        pause_local_scans: @pause_local_scans,
        cancellation_window: @cancellation_window
      }
      repeat_hash = {
        type: @schedule_type,
        interval: @schedule_interval
      }
      backup_hash[:repeat_type] = repeat_hash
      backup_hash
    end

    def self.load(nsc)
      uri  = '/api/2.1/schedule_backup/'
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      hash = JSON.parse(resp, symbolize_names: true).first
      Nexpose::ScheduledBackup.from_hash(hash || [])
    end

    def self.delete(nsc)
      AJAX.delete(nsc, '/api/2.1/schedule_backup/', AJAX::CONTENT_TYPE::JSON)
    end
  end
end
