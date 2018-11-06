module Nexpose

  # Scan filter for alerting.
  # Set values to 1 to enable and 0 to disable.
  class ScanFilter
    include JsonSerializer
    # Scan events to alert on.
    attr_accessor :start, :stop, :fail, :resume, :pause

    def initialize(start = 0, stop = 0, fail = 0, resume = 0, pause = 0)
      @start, @stop, @fail, @resume, @pause = start.to_i, stop.to_i, fail.to_i, resume.to_i, pause.to_i
    end

    def self.json_initializer(filter)
      new(filter[:start] ? 1 : 0,
          filter[:stop] ? 1 : 0,
          filter[:failed] ? 1 : 0,
          filter[:resume] ? 1 : 0,
          filter[:pause] ? 1 : 0)
    end
  end

  # Vulnerability filtering for alerting.
  # Set values to 1 to enable and 0 to disable.
  class VulnFilter
    include JsonSerializer
    # Only alert on vulnerability findings with a severity level greater than this level.
    # Range is 0 to 10.
    # Values in the UI correspond as follows:
    #   Any severity: 1
    #   Severe and critical: 4
    #   Only critical: 8
    attr_accessor :severity

    # Vulnerability events to alert on.
    attr_accessor :confirmed, :unconfirmed, :potential

    def initialize(severity = 1, confirmed = 1, unconfirmed = 1, potential = 1)
      @severity, @confirmed = severity.to_i, confirmed.to_i
      @unconfirmed, @potential = unconfirmed.to_i, potential.to_i
    end

    def self.json_initializer(filter)
      new(filter[:severity] ? 1 : 0,
          filter[:unconfirmed] ? 1 : 0,
          filter[:confirmed] ? 1 : 0,
          filter[:potential] ? 1 : 0)
    end
  end

  # Alert base behavior.
  # The supported three alert types should have these properties and behaviors
  module Alert
    include JsonSerializer
    extend TypedAccessor

    # ID for this alert.
    attr_accessor :id
    # Name for this alert.
    attr_accessor :name
    # Whether or not this alert is currently active.
    attr_accessor :enabled
    # Send at most this many alerts per scan.
    attr_accessor :max_alerts
    # Alert type and its configuration. One of SMTPAlert, SyslogAlert, SNMPAlert
    attr_accessor :alert_type
    # Server target the alerts
    attr_accessor :server
    # Server port
    attr_accessor :server_port

    # Send alerts based upon scan status.
    typed_accessor :scan_filter, ScanFilter
    # Send alerts based upon vulnerability finding status.
    typed_accessor :vuln_filter, VulnFilter

    # load a particular site alert
    def self.load(nsc, site_id, alert_id)
      uri  = "/api/2.1/site_configurations/#{site_id}/alerts/#{alert_id}"
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)

      unless resp.to_s == ''
        data = JSON.parse(resp, symbolize_names: true)
        json_initializer(data).deserialize(data)
      end
    end

    # load alerts from an array of hashes
    def self.load_alerts(alerts)
      alerts.map { |hash| json_initializer(hash).deserialize(hash) }
    end

    # load a list of alerts for a given site
    def self.list_alerts(nsc, site_id)
      uri  = "/api/2.1/site_configurations/#{site_id}/alerts"
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      data = JSON.parse(resp, symbolize_names: true)
      load_alerts(data) unless data.nil?
    end

    def self.json_initializer(hash)
      create(hash)
    end

    def to_h
      to_hash(Hash.new)
    end

    def to_json
      serialize
    end

    # delete an alert from the given site
    def delete(nsc, site_id)
      uri = "/api/2.1/site_configurations/#{site_id}/alerts/#{id}"
      AJAX.delete(nsc, uri, AJAX::CONTENT_TYPE::JSON)
    end

    # save an alert for a given site
    def save(nsc, site_id)
      validate
      uri = "/api/2.1/site_configurations/#{site_id}/alerts"
      id  = AJAX.put(nsc, uri, self.to_json, AJAX::CONTENT_TYPE::JSON)
      @id = id.to_i
    end

    def validate
      raise ArgumentError.new('Name is a required attribute.') unless @name
      raise ArgumentError.new('Scan filter is a required attribute.') unless @scan_filter
      raise ArgumentError.new('Vuln filter is a required attribute.') unless @vuln_filter
    end

    def self.create(hash)
      alert_type = hash[:alert_type]
      raise 'An alert must have an alert type' if alert_type.nil?
      raise 'Alert name cannot be empty.' if !hash.key?(:name) || hash[:name].to_s == ''
      raise 'SNMP and Syslog alerts must have a server defined' if ['SNMP', 'Syslog'].include?(alert_type) && hash[:server].to_s == ''

      case alert_type
      when 'SMTP'
        alert = SMTPAlert.new(hash[:name],
                              hash[:sender],
                              hash[:server],
                              hash[:recipients],
                              hash[:enabled],
                              hash[:max_alerts],
                              hash[:verbose])
      when 'SNMP'
        alert = SNMPAlert.new(hash[:name],
                              hash[:community],
                              hash[:server],
                              hash[:enabled],
                              hash[:max_alerts])
      when 'Syslog'
        alert = SyslogAlert.new(hash[:name],
                                hash[:server],
                                hash[:enabled],
                                hash[:max_alerts])
      else
        fail "Unknown alert type: #{alert_type}"
      end

      alert.scan_filter = ScanFilter.new
      alert.vuln_filter = VulnFilter.new
      alert
    end
  end

  # SMTP (e-mail) Alert
  class SMTPAlert
    include Alert
    attr_accessor :recipients, :sender, :verbose

    def initialize(name, sender, server, recipients, enabled = 1, max_alerts = -1, verbose = 0)
      unless recipients.is_a?(Array) && !recipients.empty?
        raise 'An SMTP alert must contain an array of recipient emails with at least 1 recipient'
      end

      recipients.each do |recipient|
        unless recipient =~ /^.+@.+\..+$/
          raise "Recipients must contain valid emails, #{recipient} has an invalid format"
        end
      end

      @alert_type = 'SMTP'
      @name       = name
      @enabled    = enabled
      @max_alerts = max_alerts
      @sender     = sender
      @server     = server
      @verbose    = verbose
      @recipients = recipients.nil? ? [] : recipients
    end

    def add_email_recipient(recipient)
      @recipients << recipient
    end

    def remove_email_recipient(recipient)
      @recipients.delete(recipient)
    end
  end

  # SNMP Alert
  class SNMPAlert
    include Alert
    attr_accessor :community

    def initialize(name, community, server, enabled = 1, max_alerts = -1)
      raise 'SNMP alerts must have a community defined.' if community.nil?
      @alert_type = 'SNMP'
      @name       = name
      @enabled    = enabled
      @max_alerts = max_alerts
      @community  = community
      @server     = server
    end
  end

  # Syslog Alert
  class SyslogAlert
    include Alert

    def initialize(name, server, enabled = 1, max_alerts = -1)
      @alert_type = 'Syslog'
      @name       = name
      @enabled    = enabled
      @max_alerts = max_alerts
      @server     = server
    end
  end

end
