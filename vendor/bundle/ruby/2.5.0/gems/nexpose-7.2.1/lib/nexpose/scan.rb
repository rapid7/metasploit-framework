module Nexpose
  class Connection
    include XMLUtils

    # Perform an ad hoc scan of a single device.
    #
    # @param [Device] device Device to scan.
    # @return [Scan] Scan launch information.
    #
    def scan_device(device)
      scan_devices([device])
    end

    # Perform an ad hoc scan of a single device at a specific time.
    #
    # @param [Device] device Device to scan.
    # @param [Array[adhoc_schedules]] list of scheduled times at which to run
    # @return [Status] whether the request was successful
    #
    def scan_device_with_schedule(device, schedule)
      scan_devices_with_schedule([device], schedule)
    end

    # Perform an ad hoc scan of a subset of devices for a site.
    # Nexpose only allows devices from a single site to be submitted per
    # request.
    # Method is designed to take objects from a Device listing.
    #
    # For example:
    #   devices = nsc.devices(5)
    #   nsc.scan_devices(devices.take(10))
    #
    # @param [Array[Device]] devices List of devices to scan.
    # @return [Scan] Scan launch information.
    #
    def scan_devices(devices)
      site_id = devices.map(&:site_id).uniq.first
      xml = make_xml('SiteDevicesScanRequest', 'site-id' => site_id)
      elem = REXML::Element.new('Devices')
      devices.each do |device|
        elem.add_element('device', 'id' => "#{device.id}")
      end
      xml.add_element(elem)

      _scan_ad_hoc(xml)
    end

    # Perform an ad hoc scan of a subset of devices for a site.
    # Nexpose only allows devices from a single site to be submitted per
    # request.
    # Method is designed to take objects from a Device listing.
    #
    # For example:
    #   devices = nsc.devices(5)
    #   nsc.scan_devices(devices.take(10))
    #
    # @param [Array[Device]] devices List of devices to scan.
    # @param [Array[adhoc_schedules]] list of scheduled times at which to run
    # @return [Status] whether the request was successful
    #
    def scan_devices_with_schedule(devices, schedules)
      site_id = devices.map(&:site_id).uniq.first
      xml     = make_xml('SiteDevicesScanRequest', 'site-id' => site_id)
      elem    = REXML::Element.new('Devices')
      devices.each do |device|
        elem.add_element('device', 'id' => "#{device.id}")
      end
      xml.add_element(elem)
      scheds = REXML::Element.new('Schedules')
      schedules.each { |sched| scheds.add_element(sched.as_xml) }
      xml.add_element(scheds)

      _scan_ad_hoc_with_schedules(xml)
    end

    # Perform an ad hoc scan of a single asset of a site.
    #
    # @param [Fixnum] site_id Site ID that the assets belong to.
    # @param [HostName|IPRange] asset Asset to scan.
    # @return [Scan] Scan launch information.
    #
    def scan_asset(site_id, asset)
      scan_assets(site_id, [asset])
    end

    # Perform an ad hoc scan of a single asset of a site at a specific time
    #
    # @param [Fixnum] site_id Site ID that the assets belong to.
    # @param [HostName|IPRange] asset Asset to scan.
    # @param [Array[adhoc_schedules]] list of scheduled times at which to run
    # @return [Status] whether the request was successful
    #
    def scan_asset_with_schedule(site_id, asset, schedule)
      scan_assets_with_schedule(site_id, [asset], schedule)
    end

    # Perform an ad hoc scan of a subset of assets for a site.
    # Only assets from a single site should be submitted per request.
    # Method is designed to take objects filtered from Site#assets.
    #
    # For example:
    #   site = Site.load(nsc, 5)
    #   nsc.scan_assets(5, site.assets.take(10))
    #
    # @param [Fixnum] site_id Site ID that the assets belong to.
    # @param [Array[HostName|IPRange]] assets List of assets to scan.
    # @return [Scan] Scan launch information.
    #
    def scan_assets(site_id, assets)
      xml   = make_xml('SiteDevicesScanRequest', 'site-id' => site_id)
      hosts = REXML::Element.new('Hosts')
      assets.each { |asset| _append_asset!(hosts, asset) }
      xml.add_element(hosts)

      _scan_ad_hoc(xml)
    end

    # Perform an ad hoc scan of a subset of assets for a site by adding a specific runtime.
    # Only assets from a single site should be submitted per request.
    # Method is designed to take objects filtered from Site#assets.
    #
    # For example:
    #   site = Site.load(nsc, 5)
    #   nsc.scan_assets_with_schedule(5, site.assets.take(10), schedules)
    #
    # @param [Fixnum] site_id Site ID that the assets belong to.
    # @param [Array[HostName|IPRange]] assets List of assets to scan.
    # @param [Array[adhoc_schedules]] list of scheduled times at which to run
    # @return [Status] whether the request was successful
    #
    def scan_assets_with_schedule(site_id, assets, schedules)
      xml   = make_xml('SiteDevicesScanRequest', 'site-id' => site_id)
      hosts = REXML::Element.new('Hosts')
      assets.each { |asset| _append_asset!(hosts, asset) }
      xml.add_element(hosts)
      scheds = REXML::Element.new('Schedules')
      schedules.each { |sched| scheds.add_element(sched.as_xml) }
      xml.add_element(scheds)

      _scan_ad_hoc_with_schedules(xml)
    end

    # Perform an ad hoc scan of a subset of IP addresses for a site at a specific time.
    # Only IPs from a single site can be submitted per request,
    # and IP addresses must already be included in the site configuration.
    # Method is designed for scanning when the targets are coming from an
    # external source that does not have access to internal identfiers.
    #
    # For example:
    #   to_scan = ['192.168.2.1', '192.168.2.107']
    #   nsc.scan_ips(5, to_scan)
    #
    # @param [Fixnum] site_id Site ID that the assets belong to.
    # @param [Array[String]] ip_addresses Array of IP addresses to scan.
    # @return [Status] whether the request was successful
    #
    def scan_ips_with_schedule(site_id, ip_addresses, schedules)
      xml   = make_xml('SiteDevicesScanRequest', 'site-id' => site_id)
      hosts = REXML::Element.new('Hosts')
      ip_addresses.each do |ip|
        xml.add_element('range', 'from' => ip)
      end
      xml.add_element(hosts)
      scheds = REXML::Element.new('Schedules')
      schedules.each { |sched| scheds.add_element(sched.as_xml) }
      xml.add_element(scheds)

      _scan_ad_hoc_with_schedules(xml)
    end

    # Perform an ad hoc scan of a subset of IP addresses for a site.
    # Only IPs from a single site can be submitted per request,
    # and IP addresses must already be included in the site configuration.
    # Method is designed for scanning when the targets are coming from an
    # external source that does not have access to internal identfiers.
    #
    # For example:
    #   to_scan = ['192.168.2.1', '192.168.2.107']
    #   nsc.scan_ips(5, to_scan)
    #
    # @param [Fixnum] site_id Site ID that the assets belong to.
    # @param [Array[String]] ip_addresses Array of IP addresses to scan.
    # @return [Scan] Scan launch information.
    #
    def scan_ips(site_id, ip_addresses)
      xml   = make_xml('SiteDevicesScanRequest', 'site-id' => site_id)
      hosts = REXML::Element.new('Hosts')
      ip_addresses.each do |ip|
        xml.add_element('range', 'from' => ip)
      end
      xml.add_element(hosts)

      _scan_ad_hoc(xml)
    end

    # Initiate a site scan.
    #
    # @param [Fixnum] site_id Site ID to scan.
    # @param [Boolean] blackout_override Optional. Given suffencent permissions, force bypass blackout and start scan.
    # @return [Scan] Scan launch information.
    #
    def scan_site(site_id, blackout_override = false)
      xml = make_xml('SiteScanRequest', 'site-id' => site_id)
      xml.add_attributes({ 'force' => true }) if blackout_override
      response = execute(xml)
      Scan.parse(response.res) if response.success
    end

    # Initiate an ad-hoc scan on a subset of site assets with
    # a specific scan template and scan engine, which may differ
    # from the site's defined scan template and scan engine.
    #
    # @param [Fixnum] site_id Site ID to scan.
    # @param [Array[String]] assets Hostnames and/or IP addresses to scan.
    # @param [String] scan_template The scan template ID.
    # @param [Fixnum] scan_engine The scan engine ID.
    # @return [Fixnum] Scan ID.
    #
    def scan_assets_with_template_and_engine(site_id, assets, scan_template, scan_engine)
      uri = "/data/site/#{site_id}/scan"
      assets.size > 1 ? addresses = assets.join(',') : addresses = assets.first
      params = { 'addressList' => addresses,
                 'template' => scan_template,
                 'scanEngine' => scan_engine }
      scan_id = AJAX.form_post(self, uri, params)
      scan_id.to_i
    end

    # Utility method for appending a HostName or IPRange object into an
    # XML object, in preparation for ad hoc scanning.
    #
    # @param [REXML::Document] xml Prepared API call to execute.
    # @param [HostName|IPRange] asset Asset to append to XML.
    #
    def _append_asset!(xml, asset)
      if asset.is_a? Nexpose::IPRange
        xml.add_element('range', 'from' => asset.from, 'to' => asset.to)
      else # Assume HostName
        host = REXML::Element.new('host')
        host.text = asset
        xml.add_element(host)
      end
    end

    # Utility method for executing prepared XML and extracting Scan launch
    # information.
    #
    # @param [REXML::Document] xml Prepared API call to execute.
    # @return [Scan] Scan launch information.
    #
    def _scan_ad_hoc(xml)
      r = execute(xml, '1.1', timeout: 60)
      Scan.parse(r.res)
    end

    # Utility method for executing prepared XML for adhoc with schedules
    #
    # @param [REXML::Document] xml Prepared API call to execute.
    #
    def _scan_ad_hoc_with_schedules(xml)
      r = execute(xml, '1.1', timeout: 60)
      r.success
    end

    # Stop a running or paused scan.
    #
    # @param [Fixnum] scan_id ID of the scan to stop.
    # @param [Fixnum] wait_sec Number of seconds to wait for status to be
    #   updated.
    #
    def stop_scan(scan_id, wait_sec = 0)
      r = execute(make_xml('ScanStopRequest', 'scan-id' => scan_id))
      if r.success
        so_far = 0
        while so_far < wait_sec
          status = scan_status(scan_id)
          return status if status == 'stopped'
          sleep 5
          so_far += 5
        end
      end
      r.success
    end

    # Retrieve the status of a scan.
    #
    # @param [Fixnum] scan_id The scan ID.
    # @return [String] Current status of the scan. See Nexpose::Scan::Status.
    #
    def scan_status(scan_id)
      r = execute(make_xml('ScanStatusRequest', 'scan-id' => scan_id))
      r.success ? r.attributes['status'] : nil
    end

    # Resumes a scan.
    #
    # @param [Fixnum] scan_id The scan ID.
    #
    def resume_scan(scan_id)
      r = execute(make_xml('ScanResumeRequest', 'scan-id' => scan_id), '1.1', timeout: 60)
      r.success ? r.attributes['success'] == '1' : false
    end

    # Pauses a scan.
    #
    # @param [Fixnum] scan_id The scan ID.
    #
    def pause_scan(scan_id)
      r = execute(make_xml('ScanPauseRequest', 'scan-id' => scan_id))
      r.success ? r.attributes['success'] == '1' : false
    end

    # Retrieve a list of current scan activities across all Scan Engines
    # managed by Nexpose. This method returns lighter weight objects than
    # scan_activity.
    #
    # @return [Array[ScanData]] Array of ScanData objects associated with
    #   each active scan on the engines.
    #
    def activity
      r = execute(make_xml('ScanActivityRequest'))
      res = []
      if r.success
        r.res.elements.each('//ScanSummary') do |scan|
          res << ScanData.parse(scan)
        end
      end
      res
    end

    # Retrieve a list of current scan activities across all Scan Engines
    # managed by Nexpose.
    #
    # @return [Array[ScanSummary]] Array of ScanSummary objects associated with
    #   each active scan on the engines.
    #
    def scan_activity
      r = execute(make_xml('ScanActivityRequest'))
      res = []
      if r.success
        r.res.elements.each('//ScanSummary') do |scan|
          res << ScanSummary.parse(scan)
        end
      end
      res
    end

    # Get scan statistics, including node and vulnerability breakdowns.
    #
    # @param [Fixnum] scan_id Scan ID to retrieve statistics for.
    # @return [ScanSummary] ScanSummary object providing statistics for the scan.
    #
    def scan_statistics(scan_id)
      r = execute(make_xml('ScanStatisticsRequest', 'scan-id' => scan_id))
      if r.success
        ScanSummary.parse(r.res.elements['//ScanSummary'])
      else
        false
      end
    end

    # Get a history of past scans for this console, sorted by most recent first.
    #
    # Please note that for consoles with a deep history of scanning, this method
    # could return an excessive amount of data (and take quite a bit of time to
    # retrieve). Consider limiting the amount of data with the optional argument.
    #
    # @param [Fixnum] limit The maximum number of records to return from this call.
    # @return [Array[CompletedScan]] List of completed scans, ordered by most
    #   recently completed first.
    #
    def past_scans(limit = nil)
      uri    = '/data/scan/global/scan-history'
      rows   = AJAX.row_pref_of(limit)
      params = { 'sort' => 'endTime', 'dir' => 'DESC', 'startIndex' => 0 }
      AJAX.preserving_preference(self, 'global-completed-scans') do
        data = DataTable._get_json_table(self, uri, params, rows, limit)
        data.map(&CompletedScan.method(:parse_json))
      end
    end

    # Get paused scans. Provide a site ID to get paused scans for a site.
    # With no site ID, all paused scans are returned.
    #
    # @param [Fixnum] site_id Site ID to retrieve paused scans for.
    # @param [Fixnum] limit The maximum number of records to return from this call.
    # @return [Array[ActiveScan]] List of paused scans.
    #
    def paused_scans(site_id = nil, limit = nil)
      if site_id
        uri    = "/data/scan/site/#{site_id}?status=active"
        rows   = AJAX.row_pref_of(limit)
        params = { 'sort' => 'endTime', 'dir' => 'DESC', 'startIndex' => 0 }
        AJAX.preserving_preference(self, 'site-active-scans') do
          data = DataTable._get_json_table(self, uri, params, rows, limit).select { |scan| scan['paused'] }
          data.map(&ActiveScan.method(:parse_json))
        end
      else
        uri  = '/data/site/scans/dyntable.xml?printDocType=0&tableID=siteScansTable&activeOnly=true'
        data = DataTable._get_dyn_table(self, uri).select { |scan| (scan['Status'].include? 'Paused') }
        data.map(&ActiveScan.method(:parse_dyntable))
      end
    end

    # Export the data associated with a single scan, and optionally store it in
    # a zip-compressed file under the provided name.
    #
    # @param [Fixnum] scan_id Scan ID to remove data for.
    # @param [String] zip_file Filename to export scan data to.
    # @return [Fixnum] On success, returned the number of bytes written to
    #   zip_file, if provided. Otherwise, returns raw ZIP binary data.
    #
    def export_scan(scan_id, zip_file = nil)
      http              = AJAX.https(self)
      headers           = { 'Cookie' => "nexposeCCSessionID=#{@session_id}", 'Accept-Encoding' => 'identity' }
      resp              = http.get("/data/scan/#{scan_id}/export", headers)

      case resp
      when Net::HTTPSuccess
        if zip_file
          ::File.open(zip_file, 'wb') { |file| file.write(resp.body) }
        else
          resp.body
        end
      when Net::HTTPForbidden
        raise Nexpose::PermissionError.new(resp)
      else
        raise Nexpose::APIError.new(resp, "#{resp.class}: Unrecognized response.")
      end
    end

    # Import scan data into a site.
    #
    # This method is designed to work with export_scan to migrate scan data
    # from one console to another. This method will import the data as if run
    # from a local scan engine.
    #
    # Scan importing is restricted to only importing scans in chronological
    # order. It assumes that it is the latest scan for a given site, and will
    # abort if attempting to import an older scan.
    #
    # @param [Fixnum] site_id Site ID of the site to import the scan into.
    # @param [String] zip_file Path to a previously exported scan archive.
    # @return [Fixnum] The scan ID on success.
    #
    def import_scan(site_id, zip_file)
      data = Rexlite::MIME::Message.new
      data.add_part(site_id.to_s, nil, nil, 'form-data; name="siteid"')
      data.add_part(session_id, nil, nil, 'form-data; name="nexposeCCSessionID"')
      ::File.open(zip_file, 'rb') do |scan|
        data.add_part(scan.read, 'application/zip', 'binary',
                      "form-data; name=\"scan\"; filename=\"#{zip_file}\"")
      end

      post = Net::HTTP::Post.new('/data/scan/import')
      post.body = data.to_s
      post.set_content_type('multipart/form-data', boundary: data.bound)

      # Avoiding AJAX#request, because the data can cause binary dump on error.
      http = AJAX.https(self)
      AJAX.headers(self, post)
      response = http.request(post)
      case response
      when Net::HTTPOK
        response.body.empty? ? response.body : response.body.to_i
      when Net::HTTPUnauthorized
        raise Nexpose::PermissionError.new(response)
      else
        raise Nexpose::APIError.new(post, response.body)
      end
    end

    # Delete a scan and all its data from a console.
    # Warning, this method is destructive and not guaranteed to leave a site
    # in a valid state. DBCC may need to be run to correct missing or empty
    # assets.
    #
    # @param [Fixnum] scan_id Scan ID to remove data for.
    #
    def delete_scan(scan_id)
      AJAX.delete(self, "/data/scan/#{scan_id}")
    end
  end

  # Minimal scan data object.
  # Unlike ScanSummary, these objects don't collect vulnerability data, which
  # can be rather verbose and isn't useful for many automation scenarios.
  #
  class ScanData
    # The Scan ID of the Scan
    attr_reader :scan_id
    # The site that was scanned.
    attr_reader :site_id
    # The Engine ID the scan was dispatched to.
    attr_reader :engine_id
    # The scan start time
    attr_reader :start_time
    # The scan finish time
    attr_reader :end_time
    # The scan status.
    # One of: running|finished|stopped|error|dispatched|paused|aborted|uknown
    attr_reader :status

    # Constructor
    def initialize(scan_id, site_id, engine_id, status, start_time, end_time)
      @scan_id    = scan_id
      @site_id    = site_id
      @engine_id  = engine_id
      @status     = status
      @start_time = start_time
      @end_time   = end_time
    end

    def self.parse(xml)
      # Start time can be empty in some error conditions.
      start_time = nil
      unless xml.attributes['startTime'] == ''
        start_time = DateTime.parse(xml.attributes['startTime'].to_s).to_time
        # Timestamp is UTC, but parsed as local time.
        start_time -= start_time.gmt_offset
      end

      # End time is often not present, since reporting on running scans.
      end_time = nil
      if xml.attributes['endTime']
        end_time = DateTime.parse(xml.attributes['endTime'].to_s).to_time
        # Timestamp is UTC, but parsed as local time.
        end_time -= end_time.gmt_offset
      end

      ScanData.new(xml.attributes['scan-id'].to_i,
                   xml.attributes['site-id'].to_i,
                   xml.attributes['engine-id'].to_i,
                   xml.attributes['status'],
                   start_time,
                   end_time)
    end
  end

  # Object that represents a summary of a scan.
  #
  class ScanSummary < ScanData
    # The reason the scan was stopped or failed, if applicable.
    attr_reader :message

    # Task statistics, including pending, active, and completed tasks.
    attr_reader :tasks
    # Node statistics, including live, dead, filtered, and unresolved.
    attr_reader :nodes
    # Vulnerability statistics, including statuses, severities, and counts.
    attr_reader :vulnerabilities

    # Constructor
    def initialize(scan_id, site_id, engine_id, status, start_time, end_time, message, tasks, nodes, vulnerabilities)
      @scan_id         = scan_id
      @site_id         = site_id
      @engine_id       = engine_id
      @status          = status
      @start_time      = start_time
      @end_time        = end_time
      @message         = message
      @tasks           = tasks
      @nodes           = nodes
      @vulnerabilities = vulnerabilities
    end

    # Parse a response from a Nexpose console into a valid ScanSummary object.
    #
    # @param [REXML::Document] xml XML document to parse.
    # @return [ScanSummary] Scan summary represented by the XML.
    #
    def self.parse(xml)
      tasks = Tasks.parse(xml.elements['tasks'])
      nodes = Nodes.parse(xml.elements['nodes'])
      vulns = Vulnerabilities.parse(xml.attributes['scan-id'], xml)
      msg = xml.elements['message'] ? xml.elements['message'].text : nil

      # Start time can be empty in some error conditions.
      start_time = nil
      unless xml.attributes['startTime'] == ''
        start_time = DateTime.parse(xml.attributes['startTime'].to_s).to_time
        # Timestamp is UTC, but parsed as local time.
        start_time -= start_time.gmt_offset
      end

      # End time is often not present, since reporting on running scans.
      end_time = nil
      if xml.attributes['endTime']
        end_time = DateTime.parse(xml.attributes['endTime'].to_s).to_time
        # Timestamp is UTC, but parsed as local time.
        end_time -= end_time.gmt_offset
      end
      ScanSummary.new(xml.attributes['scan-id'].to_i,
                      xml.attributes['site-id'].to_i,
                      xml.attributes['engine-id'].to_i,
                      xml.attributes['status'],
                      start_time,
                      end_time,
                      msg,
                      tasks,
                      nodes,
                      vulns)
    end

    # Value class to tracking task counts.
    #
    class Tasks
      attr_reader :pending, :active, :completed

      def initialize(pending, active, completed)
        @pending   = pending
        @active    = active
        @completed = completed
      end

      # Parse REXML to Tasks object.
      #
      # @param [REXML::Document] rexml XML document to parse.
      # @return [Tasks] Task summary represented by the XML.
      #
      def self.parse(rexml)
        return nil unless rexml
        Tasks.new(rexml.attributes['pending'].to_i,
                  rexml.attributes['active'].to_i,
                  rexml.attributes['completed'].to_i)
      end
    end

    # Value class for tracking node counts.
    #
    class Nodes
      attr_reader :live, :dead, :filtered, :unresolved, :other

      def initialize(live, dead, filtered, unresolved, other)
        @live       = live
        @dead       = dead
        @filtered   = filtered
        @unresolved = unresolved
        @other      = other
      end

      # Parse REXML to Nodes object.
      #
      # @param [REXML::Document] rexml XML document to parse.
      # @return [Nodes] Node summary represented by the XML.
      #
      def self.parse(rexml)
        return nil unless rexml
        Nodes.new(rexml.attributes['live'].to_i,
                  rexml.attributes['dead'].to_i,
                  rexml.attributes['filtered'].to_i,
                  rexml.attributes['unresolved'].to_i,
                  rexml.attributes['other'].to_i)
      end
    end

    # Value class for tracking vulnerability counts.
    #
    class Vulnerabilities
      attr_reader :vuln_exploit, :vuln_version, :vuln_potential, :not_vuln_exploit, :not_vuln_version, :error, :disabled, :other

      def initialize(vuln_exploit, vuln_version, vuln_potential, not_vuln_exploit, not_vuln_version, error, disabled, other)
        @vuln_exploit     = vuln_exploit
        @vuln_version     = vuln_version
        @vuln_potential   = vuln_potential
        @not_vuln_exploit = not_vuln_exploit
        @not_vuln_version = not_vuln_version
        @error            = error
        @disabled         = disabled
        @other            = other
      end

      # Parse REXML to Vulnerabilities object.
      #
      # @param [FixNum] scan_id Scan ID to collect vulnerability data for.
      # @param [REXML::Document] rexml XML document to parse.
      # @return [Vulnerabilities] Vulnerability summary represented by the XML.
      #
      def self.parse(scan_id, rexml)
        return nil unless rexml
        map = {}
        rexml.elements.each("//ScanSummary[contains(@scan-id,'#{scan_id}')]/vulnerabilities") do |vuln|
          status = map[vuln.attributes['status']]
          if status && vuln.attributes['status'] =~ /^vuln-/
            status.add_severity(vuln.attributes['severity'].to_i, vuln.attributes['count'].to_i)
          else
            map[vuln.attributes['status']] = Status.new(vuln.attributes['severity'], vuln.attributes['count'].to_i)
          end
        end
        Vulnerabilities.new(map['vuln-exploit'],
                            map['vuln-version'],
                            map['vuln-potential'],
                            map['not-vuln-exploit'],
                            map['not-vuln-version'],
                            map['error'],
                            map['disabled'],
                            map['other'])
      end

      # Value class for tracking vulnerability status counts.
      #
      # Severities will only be mapped if they are provided in the response,
      # which currently only happens for vuln-exploit, vuln-version,
      # and vuln-potential.
      #
      class Status
        attr_reader :severities, :count

        def initialize(severity = nil, count = 0)
          if severity
            @severities = {}
            @count      = 0
            add_severity(severity.to_i, count)
          else
            @severities = nil
            @count      = count
          end
        end

        # For vuln-exploit, vuln-version, and vuln-potential,
        # map the count at a severity level, but also maintain an overall count.
        def add_severity(severity, count)
          @count += count
          @severities[severity] = count
        end
      end
    end
  end

  # Struct class for tracking scan launch information.
  #
  class Scan
    # The scan ID when a scan is successfully launched.
    attr_reader :id
    # The engine the scan was dispatched to.
    attr_reader :engine

    def initialize(scan_id, engine_id)
      @id     = scan_id
      @engine = engine_id
    end

    def self.parse(xml)
      xml.elements.each('//Scan') do |scan|
        return new(scan.attributes['scan-id'].to_i,
                   scan.attributes['engine-id'].to_i)
      end
    end

    # Scan status constants. These are all the possible values which may be
    # returned by a #scan_status call.
    #
    module Status
      RUNNING     = 'running'
      FINISHED    = 'finished'
      ABORTED     = 'aborted'
      STOPPED     = 'stopped'
      ERROR       = 'error'
      PAUSED      = 'paused'
      DISPATCHED  = 'dispatched'
      UNKNOWN     = 'unknown'
      INTEGRATING = 'integrating'
    end
  end

  # Summary object of a completed scan for a site.
  #
  class CompletedScan
    # Unique identifier of a scan.
    attr_reader :id
    # Site ID for which the scan was run.
    attr_reader :site_id
    # Final status of the scan. One of :completed, :stopped, :aborted, :unknown.
    attr_reader :status
    # Start time of the scan.
    attr_reader :start_time
    # Completion time of the scan.
    attr_reader :end_time
    # Elapsed time of the scan in milliseconds.
    attr_reader :duration
    # Number of vulnerabilities discovered in the scan.
    attr_reader :vulns
    # Number of live assets discovered in the scan.
    attr_reader :assets
    # Cumulative risk score for all assets in the scan.
    attr_reader :risk_score
    # Scan type. One of :scheduled or :manual
    attr_reader :type
    # Name of the engine where the scan was run. Not the unique ID.
    attr_reader :engine_name
    # Name of the scan that was assigned.
    attr_reader :scan_name

    # Internal constructor to be called by #parse_json.
    def initialize(&block)
      instance_eval(&block) if block_given?
    end

    # Internal method for converting a JSON representation into a CompletedScan
    # object.
    def self.parse_json(json)
      new do
        @id          = json['scanID']
        @site_id     = json['siteID']
        @status      = CompletedScan._parse_status(json['status'])
        @start_time  = Time.at(json['startTime'] / 1000)
        @end_time    = Time.at(json['endTime'] / 1000)
        @duration    = json['duration']
        @vulns       = json['vulnerabilityCount']
        @assets      = json['liveHosts']
        @risk_score  = json['riskScore']
        @type        = json['startedByCD'] == 'S' ? :scheduled : :manual
        @engine_name = json['scanEngineName']
        @scan_name   = json['scanName']
      end
    end

    # Internal method to parsing status codes.
    def self._parse_status(code)
      case code
      when 'C'
        :completed
      when 'S'
        :stopped
      when 'A'
        :aborted
      else
        :unknown
      end
    end
  end

  class ActiveScan < CompletedScan
    def self.parse_dyntable(json)
      new do
        @id          = json['Scan ID']
        @site_id     = json['Site ID']
        @status      = CompletedScan._parse_status(json['Status Code'])
        @start_time  = Time.at(json['Started'].to_i / 1000)
        @end_time    = Time.at(json['Progress'].to_i / 1000)
        @duration    = json['Elapsed'].to_i
        @vulns       = json['Vulnerabilities Discovered'].to_i
        @assets      = json['Devices Discovered'].to_i
        @risk_score  = json['riskScore']
        @type        = json['Scan Type'] == 'Manual' ? :manual : :scheduled
        @engine_name = json['Scan Engine']
        @scan_name   = json['Scan Name']
      end
    end

    # Internal method to parsing status codes.
    def self._parse_status(code)
      case code
      when 'U'
        :running
      when 'P'
        :paused
      when 'I'
        :integrating
      else
        :unknown
      end
    end
  end
end
