module Nexpose

  class Connection
    include XMLUtils

    # Provide a listing of all report definitions the user can access on the
    # Security Console.
    #
    # @return [Array[ReportConfigSummary]] List of current report configuration.
    #
    def list_reports
      r = execute(make_xml('ReportListingRequest'))
      reports = []
      if r.success
        r.res.elements.each('//ReportConfigSummary') do |report|
          reports << ReportConfigSummary.parse(report)
        end
      end
      reports
    end

    alias reports list_reports

    # Generate a new report using the specified report definition.
    def generate_report(report_id, wait = false)
      xml = make_xml('ReportGenerateRequest', { 'report-id' => report_id })
      response = execute(xml)
      if response.success
        response.res.elements.each('//ReportSummary') do |summary|
          summary = ReportSummary.parse(summary)
          # If not waiting or the report is finished, return now.
          return summary unless wait && summary.status == 'Started'
        end
      end
      so_far = 0
      while wait
        summary = last_report(report_id)
        return summary unless summary.status == 'Started'
        sleep 5
        so_far += 5
        if (so_far % 60).zero?
          puts "Still waiting. Current status: #{summary.status}"
        end
      end
      nil
    end

    # Provide a history of all reports generated with the specified report
    # definition.
    def report_history(report_config_id)
      xml = make_xml('ReportHistoryRequest', { 'reportcfg-id' => report_config_id })
      ReportSummary.parse_all(execute(xml))
    end

    # Get details of the last report generated with the specified report id.
    def last_report(report_config_id)
      history = report_history(report_config_id)
      history.sort { |a, b| b.generated_on <=> a.generated_on }.first
    end

    # Delete a previously generated report.
    #
    # @param [Fixnum] report_id ID of individual report to delete.
    #
    def delete_report(report_id)
      xml = make_xml('ReportDeleteRequest', { 'report-id' => report_id })
      execute(xml).success
    end

    # Delete a previously generated report definition.
    # Also deletes any reports generated from that configuration.
    #
    # @param [Fixnum] report_config_id ID of the report configuration to remove.
    #
    def delete_report_config(report_config_id)
      xml = make_xml('ReportDeleteRequest', { 'reportcfg-id' => report_config_id })
      execute(xml).success
    end
  end

  # Data object for report configuration information.
  # Not meant for use in creating new configurations.
  #
  class ReportConfigSummary

    # The report definition (config) ID.
    attr_reader :config_id
    # The report config name.
    attr_reader :name
    # The ID of the report template.
    attr_reader :template_id
    # The current status of the report.
    # One of: Started|Generated|Failed|Aborted|Unknown
    attr_reader :status
    # The date and time the report was generated, in ISO 8601 format.
    attr_reader :generated_on
    # The URL to use to access the report (not set for database exports).
    attr_reader :uri
    # The visibility (scope) of the report definition.
    # One of: (global|silo).
    attr_reader :scope

    def initialize(config_id, name, template_id, status, generated_on, uri, scope)
      @config_id    = config_id.to_i
      @name         = name
      @template_id  = template_id
      @status       = status
      @generated_on = generated_on
      @uri          = uri
      @scope        = scope
    end

    def self.parse(xml)
      ReportConfigSummary.new(xml.attributes['cfg-id'].to_i,
                              xml.attributes['name'],
                              xml.attributes['template-id'],
                              xml.attributes['status'],
                              xml.attributes['generated-on'],
                              xml.attributes['report-URI'],
                              xml.attributes['scope'])
    end
  end

  # Summary of a single report.
  #
  class ReportSummary

    # The ID of the generated report.
    attr_reader :id
    # The report definition (configuration) ID.
    attr_reader :config_id
    # The current status of the report.
    # One of: Started|Generated|Failed|Aborted|Unknown
    attr_reader :status
    # The date and time the report was generated, in ISO 8601 format.
    attr_reader :generated_on
    # The relative URI to use to access the report.
    attr_reader :uri

    def initialize(id, config_id, status, generated_on, uri)
      @id           = id
      @config_id    = config_id.to_i
      @status       = status
      @generated_on = generated_on
      @uri          = uri
    end

    # Delete this report.
    def delete(connection)
      connection.delete_report(@id)
    end

    def self.parse(xml)
      ReportSummary.new(xml.attributes['id'],
                        xml.attributes['cfg-id'],
                        xml.attributes['status'],
                        xml.attributes['generated-on'],
                        xml.attributes['report-URI'])
    end

    def self.parse_all(response)
      summaries = []
      if response.success
        response.res.elements.each('//ReportSummary') do |summary|
          summaries << ReportSummary.parse(summary)
        end
      end
      summaries
    end
  end

  # Definition object for an adhoc report configuration.
  #
  # NOTE: XML reports only return the text of the report, but no images.
  #
  class AdhocReportConfig
    # The ID of the report template used.
    attr_accessor :template_id
    # Format. One of: pdf|html|rtf|xml|text|csv|db|raw-xml|raw-xml-v2|ns-xml|qualys-xml
    attr_accessor :format
    attr_accessor :owner
    attr_accessor :time_zone
    attr_accessor :language

    # Array of filters associated with this report.
    attr_accessor :filters
    # Baseline comparison highlights the changes between two scans, including
    # newly discovered assets, services and vulnerabilities, assets and services
    # that are no longer available and vulnerabilities that were mitigated or
    # fixed. The current scan results can be compared against the results of the
    # first scan, the most recent (previous) scan, or the scan results from a
    # particular date.
    attr_accessor :baseline

    def initialize(template_id, format, site_id = nil, owner = nil, time_zone = nil)
      @template_id = template_id
      @format      = format
      @owner       = owner
      @time_zone   = time_zone

      @filters     = []
      @filters << Filter.new('site', site_id) if site_id
    end

    # Add a new filter to this report configuration.
    def add_filter(type, id)
      filters << Filter.new(type, id)
    end

    # Add the common vulnerability status filters as used by the UI for export
    # and jasper report templates (the default filters). Recommended for reports
    # that do not require 'not vulnerable' results to be included. The following
    # statuses are added: vulnerable-exploted, vulnerable-version, and potential.
    def add_common_vuln_status_filters
      ['vulnerable-exploited', 'vulnerable-version', 'potential'].each do |vuln_status|
        filters << Filter.new('vuln-status', vuln_status)
      end
    end

    def to_xml
      xml = %(<AdhocReportConfig format="#{@format}" template-id="#{@template_id}")
      xml << %( owner="#{@owner}") if @owner
      xml << %( timezone="#{@time_zone}") if @time_zone
      xml << %( language="#{@language}") if @language
      xml << '>'

      xml << '<Filters>'
      @filters.each { |filter| xml << filter.to_xml }
      xml << '</Filters>'

      xml << %(<Baseline compareTo="#{@baseline}"/>) if @baseline
      xml << '</AdhocReportConfig>'
    end

    # Generate a report once using a simple configuration.
    #
    # For XML-based reports, only the textual report is returned and not any images.
    #
    # @param [Connection] connection Nexpose connection.
    # @param [Fixnum] timeout How long, in seconds, to wait for the report to
    #   generate. Larger reports can take a significant amount of time.
    # @param [Boolean] raw Whether to bypass response parsing an use the raw
    #   response. If this option is used, error will only be exposed by
    #   examining Connection#response_xml.
    # @return Report in text format except for PDF, which returns binary data.
    #
    def generate(connection, timeout = 300, raw = false)
      xml = %(<ReportAdhocGenerateRequest session-id="#{connection.session_id}">)
      xml << to_xml
      xml << '</ReportAdhocGenerateRequest>'
      response = connection.execute(xml, '1.1', timeout: timeout, raw: raw)
      if response.success
        content_type_response = response.raw_response.header['Content-Type']
        if content_type_response =~ /multipart\/mixed;\s*boundary=([^\s]+)/
          # Nexpose sends an incorrect boundary format which breaks parsing
          # e.g., boundary=XXX; charset=XXX
          # Fix by removing everything from the last semi-colon onward.
          last_semi_colon_index = content_type_response.index(/;/, content_type_response.index(/boundary/))
          content_type_response = content_type_response[0, last_semi_colon_index]

          data = 'Content-Type: ' + content_type_response + "\r\n\r\n" + response.raw_response_data
          doc = Rexlite::MIME::Message.new(data)
          doc.parts.each do |part|
            if /.*base64.*/ =~ part.header.to_s
              if @format =~ /(?:ht|x)ml/
                if part.header.to_s =~ %r(text/xml)
                  return part.content.unpack('m*')[0].to_s
                elsif part.header.to_s =~ %r(text/html)
                  return part.content.unpack('m*')[0].to_s
                end
              else # text|pdf|csv|rtf
                return part.content.unpack('m*')[0]
              end
            end
          end
        end
      end
    end
  end

  # Definition object for a report configuration.
  class ReportConfig < AdhocReportConfig
    # The ID of the report definition (config).
    # Use -1 to create a new definition.
    attr_accessor :id
    # The unique name assigned to the report definition.
    attr_accessor :name

    # Description associated with this report.
    attr_accessor :description
    # Array of user IDs which have access to resulting reports.
    attr_accessor :users
    # Configuration of when a report is generated.
    attr_accessor :frequency
    # Report delivery configuration.
    attr_accessor :delivery
    # Database export configuration.
    attr_accessor :db_export

    # Construct a basic ReportConfig object.
    def initialize(name, template_id, format, id = -1, owner = nil, time_zone = nil)
      @name        = name
      @template_id = template_id
      @format      = format
      @id          = id
      @owner       = owner
      @time_zone   = time_zone
      @filters     = []
      @users       = []
    end

    # Retrieve the configuration for an existing report definition.
    def self.load(connection, report_config_id)
      xml = %(<ReportConfigRequest session-id='#{connection.session_id}' reportcfg-id='#{report_config_id}'/>)
      ReportConfig.parse(connection.execute(xml))
    end

    alias get load

    # Build and save a report configuration against the specified site using
    # the supplied type and format.
    #
    # Returns the new configuration.
    def self.build(connection, site_id, site_name, type, format, generate_now = false)
      name = %(#{site_name} #{type} report in #{format})
      config = ReportConfig.new(name, type, format)
      config.frequency = Frequency.new(true, false) unless generate_now
      config.filters << Filter.new('site', site_id)
      config.save(connection, generate_now)
      config
    end

    # Save the configuration of this report definition.
    def save(connection, generate_now = false)
      xml = %(<ReportSaveRequest session-id="#{connection.session_id}" generate-now="#{generate_now ? 1 : 0}">)
      xml << to_xml
      xml << '</ReportSaveRequest>'
      response = connection.execute(xml)
      if response.success
        @id = response.attributes['reportcfg-id'].to_i
      end
    end

    # Generate a new report using this report definition.
    def generate(connection, wait = false)
      connection.generate_report(@id, wait)
    end

    # Delete this report definition from the Security Console.
    # Deletion will also remove all reports previously generated from the
    # configuration.
    def delete(connection)
      connection.delete_report_config(@id)
    end

    include Sanitize

    def to_xml
      xml = %(<ReportConfig format="#{@format}" id="#{@id}" name="#{replace_entities(@name)}" template-id="#{@template_id}")
      xml << %( owner="#{@owner}") if @owner
      xml << %( timezone="#{@time_zone}") if @time_zone
      xml << %( language="#{@language}") if @language
      xml << '>'
      xml << %(<description>#{@description}</description>) if @description

      xml << '<Filters>'
      @filters.each { |filter| xml << filter.to_xml }
      xml << '</Filters>'

      xml << '<Users>'
      @users.each { |user| xml << %(<user id="#{user}"/>) }
      xml << '</Users>'

      xml << %(<Baseline compareTo="#{@baseline}"/>) if @baseline
      xml << @frequency.to_xml if @frequency
      xml << @delivery.to_xml if @delivery
      xml << @db_export.to_xml if @db_export

      xml << '</ReportConfig>'
    end

    def self.parse(xml)
      xml.res.elements.each('//ReportConfig') do |cfg|
        config = ReportConfig.new(cfg.attributes['name'],
                                  cfg.attributes['template-id'],
                                  cfg.attributes['format'],
                                  cfg.attributes['id'].to_i,
                                  cfg.attributes['owner'].to_i,
                                  cfg.attributes['timezone'])

        cfg.elements.each('//description') do |desc|
          config.description = desc.text
        end

        config.filters = Filter.parse(xml)

        cfg.elements.each('//user') do |user|
          config.users << user.attributes['id'].to_i
        end

        cfg.elements.each('//Baseline') do |baseline|
          config.baseline = baseline.attributes['compareTo']
        end

        config.frequency = Frequency.parse(cfg)
        config.delivery = Delivery.parse(cfg)
        config.db_export = DBExport.parse(cfg)

        return config
      end
      nil
    end
  end

  # Object that represents a report filter which determines which sites, asset
  # groups, and/or assets that a report is run against.
  #
  # The configuration must include at least one of asset, site,
  # group (asset group) or scan filter to define the scope of report.
  # The vuln-status filter can be used only with raw report formats: csv
  # or raw_xml. If the vuln-status filter is not included in the configuration,
  # all the vulnerability test results (including invulnerable instances) are
  # exported by default in csv and raw_xml reports.
  #
  class Filter
    include Sanitize

    # The ID of the specific site, group, asset, or scan.
    # For scan, this can also be "last" for the most recently run scan.
    # For vuln-status, the ID can have one of the following values:
    # 1. vulnerable-exploited (The check was positive. An exploit verified the vulnerability.)
    # 2. vulnerable-version (The check was positive. The version of the scanned service or software is associated with known vulnerabilities.)
    # 3. potential (The check for a potential vulnerability was positive.)
    # These values are supported for CSV and XML formats.
    attr_reader :id
    # One of: site|group|device|scan|vuln-categories|vuln-severity|vuln-status|cyberscope-component|cyberscope-bureau|cyberscope-enclave|tag
    attr_reader :type

    def initialize(type, id)
      @type = type
      @id = id
    end

    def to_xml
      %(<filter id="#{replace_entities(@id)}" type="#{@type}" />)
    end

    def ==(other)
      other.equal?(self) || (other.instance_of?(self.class) && other.type == @type && other.id == @id)
    end

    def self.parse(xml)
      filters = []
      xml.res.elements.each('//Filters/filter') do |filter|
        filters << Filter.new(filter.attributes['type'], filter.attributes['id'])
      end
      filters
    end
  end

  # Data object associated with when a report is generated.
  #
  class Frequency

    # Will the report be generated after a scan completes (true),
    # or is it ad hoc/scheduled (false).
    attr_accessor :after_scan
    # Whether or not a scan is scheduled.
    attr_accessor :scheduled
    # Schedule associated with the report.
    attr_accessor :schedule

    def initialize(after_scan, scheduled, schedule = nil)
      @after_scan = after_scan
      @scheduled  = scheduled
      @schedule   = schedule
    end

    def to_xml
      xml = %(<Generate after-scan="#{@after_scan ? 1 : 0}" schedule="#{@scheduled ? 1 : 0}">)
      xml << @schedule.to_xml if @schedule
      xml << '</Generate>'
    end

    def self.parse(xml)
      xml.elements.each('//Generate') do |generate|
        if generate.attributes['after-scan'] == '1'
          return Frequency.new(true, false)
        else
          if generate.attributes['schedule'] == '1'
            generate.elements.each('Schedule') do |sched|
              schedule = Schedule.parse(sched)
              return Frequency.new(false, true, schedule)
            end
          end
          return Frequency.new(false, false)
        end
      end
      nil
    end
  end

  # Data object for configuration of where a report is stored or delivered.
  #
  class Delivery

    # Whether to store report on server.
    attr_accessor :store_on_server
    # Directory location to store report in (for non-default storage).
    attr_accessor :location
    # E-mail configuration.
    attr_accessor :email

    def initialize(store_on_server, location = nil, email = nil)
      @store_on_server = store_on_server
      @location = location
      @email = email
    end

    def to_xml
      xml = '<Delivery>'
      xml << %(<Storage storeOnServer="#{@store_on_server ? 1 : 0}">)
      xml << %(<location>#{@location}</location>) if @location
      xml << '</Storage>'
      xml << @email.to_xml if @email
      xml << '</Delivery>'
    end

    def self.parse(xml)
      xml.elements.each('//Delivery') do
        on_server = false
        location = nil
        xml.elements.each('//Storage') do |storage|
          on_server = true if storage.attributes['storeOnServer'] == '1'
          xml.elements.each('//location') do |loc|
            location = loc.text
          end
        end

        email = Email.parse(xml)

        return Delivery.new(on_server, location, email)
      end
      nil
    end
  end

  # Configuration structure for database exporting of reports.
  #
  class DBExport

    # The DB type to export to.
    attr_accessor :type
    # Credentials needed to export to the specified database.
    attr_accessor :credentials
    # Map of parameters for this DB export configuration.
    attr_accessor :parameters

    def initialize(type)
      @type = type
      @parameters = {}
    end

    def to_xml
      xml = %(<DBExport type="#{@type}">)
      xml << @credentials.to_xml if @credentials
      @parameters.each_pair do |name, value|
        xml << %(<param name="#{name}">#{value}</param>)
      end
      xml << '</DBExport>'
    end

    def self.parse(xml)
      xml.elements.each('//DBExport') do |dbexport|
        config = DBExport.new(dbexport.attributes['type'])
        config.credentials = ExportCredential.parse(xml)
        xml.elements.each('//param') do |param|
          config.parameters[param.attributes['name']] = param.text
        end
        return config
      end
      nil
    end
  end

  # DBExport credentials configuration object.
  #
  # The user_id, password and realm attributes should ONLY be used
  # if a security blob cannot be generated and the data is being
  # transmitted/stored using external encryption (e.g., HTTPS).
  #
  class ExportCredential

    # Security blob for exporting to a database.
    attr_accessor :credential
    attr_accessor :user_id
    attr_accessor :password
    # DB specific, usually the database name.
    attr_accessor :realm

    def initialize(credential)
      @credential = credential
    end

    def to_xml
      xml = '<credentials'
      xml << %( userid="#{@user_id}") if @user_id
      xml << %( password="#{@password}") if @password
      xml << %( realm="#{@realm}") if @realm
      xml << '>'
      xml << @credential if @credential
      xml << '</credentials>'
    end

    def self.parse(xml)
      xml.elements.each('//credentials') do |creds|
        credential = ExportCredential.new(creds.text)
        # The following attributes may not exist.
        credential.user_id  = creds.attributes['userid']
        credential.password = creds.attributes['password']
        credential.realm    = creds.attributes['realm']
        return credential
      end
      nil
    end
  end
end
