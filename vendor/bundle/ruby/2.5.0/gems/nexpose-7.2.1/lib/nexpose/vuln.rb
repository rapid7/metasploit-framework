module Nexpose
  class Connection
    include XMLUtils

    # Retrieve summary details of all vulnerabilities.
    #
    # @param [Boolean] full Whether or not to gather the full summary.
    #   Without the flag, only id, title, and severity are returned.
    #   It can take twice a long to retrieve full summary information.
    # @return [Array[Vulnerability|VulnerabilitySummary]] Collection of all known vulnerabilities.
    #
    def list_vulns(full = false)
      xml = make_xml('VulnerabilityListingRequest')
      # TODO: Add a flag to do stream parsing of the XML to improve performance.
      response = execute(xml, '1.2')
      vulns = []
      if response.success
        response.res.elements.each('VulnerabilityListingResponse/VulnerabilitySummary') do |vuln|
          if full
            vulns << XML::VulnerabilitySummary.parse(vuln)
          else
            vulns << XML::Vulnerability.new(vuln.attributes['id'],
                                            vuln.attributes['title'],
                                            vuln.attributes['severity'].to_i)
          end
        end
      end
      vulns
    end

    alias vulns list_vulns

    # Retrieve a list of the different vulnerability check categories.
    #
    # @return [Array[String]] Array of currently valid check categories.
    #
    def list_vuln_categories
      data = DataTable._get_dyn_table(self, '/data/vulnerability/categories/dyntable.xml?tableID=VulnCategorySynopsis')
      data.map { |c| c['Category'] }
    end

    alias vuln_categories list_vuln_categories

    # Retrieve a list of the different vulnerability check types.
    #
    # @return [Array[String]] Array of currently valid check types.
    #
    def vuln_types
      data = DataTable._get_dyn_table(self, '/data/vulnerability/checktypes/dyntable.xml?tableID=VulnCheckCategorySynopsis')
      data.map { |c| c['Category'] }
    end
    alias list_vuln_types vuln_types

    # Retrieve details for a vulnerability.
    #
    # @param [String] vuln_id Nexpose vulnerability ID, such as 'windows-duqu-cve-2011-3402'.
    # @return [VulnerabilityDetail] Details of the requested vulnerability.
    #
    def vuln_details(vuln_id)
      xml = make_xml('VulnerabilityDetailsRequest', { 'vuln-id' => vuln_id })
      response = execute(xml, '1.2')
      if response.success
        response.res.elements.each('VulnerabilityDetailsResponse/Vulnerability') do |vuln|
          return XML::VulnerabilityDetail.parse(vuln)
        end
      end
    end

    # Search for Vulnerability Checks.
    #
    # @param [String] search_term Search terms to search for.
    # @param [Boolean] partial_words Allow partial word matches.
    # @param [Boolean] all_words All words must be present.
    # @return [Array[VulnCheck]] List of matching Vulnerability Checks.
    #
    def find_vuln_check(search_term, partial_words = true, all_words = true)
      uri = "/data/vulnerability/vulnerabilities/dyntable.xml?tableID=VulnCheckSynopsis&phrase=#{URI.encode(search_term)}&allWords=#{all_words}"
      data = DataTable._get_dyn_table(self, uri)
      data.map do |vuln|
        XML::VulnCheck.new(vuln)
      end
    end

    # Find vulnerabilities by date available in Nexpose.
    # This is not the date the original vulnerability was published, but the
    # date the check was made available in Nexpose.
    #
    # @param [String] from Vulnerability publish date in format YYYY-MM-DD.
    # @param [String] to Vulnerability publish date in format YYYY-MM-DD.
    # @return [Array[VulnSynopsis]] List of vulnerabilities published in
    #   Nexpose between the provided dates.
    #
    def find_vulns_by_date(from, to = nil)
      uri = "/data/vulnerability/synopsis/dyntable.xml?addedMin=#{from}"
      uri += "&addedMax=#{to}" if to
      DataTable._get_dyn_table(self, uri).map { |v| VulnSynopsis.new(v) }
    end
  end

  # Object definitions which are derived from XML values.
  #
  module XML
    # Basic vulnerability information. Only includes ID, title, and severity.
    #
    class Vulnerability
      # The unique ID string for this vulnerability
      attr_reader :id
      # The title of this vulnerability
      attr_reader :title
      # How critical the vulnerability is on a scale of 1 to 10.
      attr_reader :severity

      def initialize(id, title, severity)
        @id       = id
        @title    = title
        @severity = severity.to_i
      end
    end

    # Vulnerability Check information.
    #
    class VulnCheck < Vulnerability
      attr_reader :check_id
      # @return [Array[String]] Categories that this check is a member of.
      #   Note that this is note the same as the categories from #list_vuln_categories.
      attr_reader :categories
      # @return [String] Check type. @see #list_vuln_types
      attr_reader :check_type

      def initialize(json)
        @id         = json['Vuln ID']
        @check_id   = json['Vuln Check ID']
        @title      = json['Vulnerability']
        @severity   = json['Severity'].to_i
        @check_type = json['Check Type']
        @categories = json['Category'].split(/, */)
      end
    end

    # Summary of a vulnerability.
    #
    class VulnerabilitySummary < Vulnerability
      # PCI severity value for the vulnerability on a scale of 1 to 5.
      attr_accessor :pci_severity
      # Whether all checks for the vulnerability are safe.
      # Unsafe checks may cause denial of service or otherwise disrupt system performance.
      attr_accessor :safe
      # A vulnerability is considered "credentialed" when all of its checks
      # require credentials or if the check depends on previous authentication
      # during a scan.
      attr_accessor :credentials
      # When this vulnerability was first included in the application.
      attr_accessor :added
      # The last date the vulnerability was modified.
      attr_accessor :modified
      # The date when the information about the vulnerability was first released.
      attr_accessor :published
      # How the vulnerability is exploited according to PCI standards.
      attr_accessor :cvss_vector
      # The computation of the Common Vulnerability Scoring System indicating
      # compliance with PCI standards on a scale from 0 to 10.0.
      attr_accessor :cvss_score

      def self.parse_attributes(xml)
        vuln = new(xml.attributes['id'],
                   xml.attributes['title'],
                   xml.attributes['severity'].to_i)

        vuln.pci_severity = xml.attributes['pciSeverity'].to_i
        vuln.safe         = xml.attributes['safe'] == 'true' # or xml.attributes['safe'] == '1'
        vuln.added        = Date.parse(xml.attributes['added'])
        vuln.modified     = Date.parse(xml.attributes['modified'])
        vuln.credentials  = xml.attributes['requiresCredentials'] == 'true'

        # These three fields are optional in the XSD.
        vuln.published    = Date.parse(xml.attributes['published']) if xml.attributes['published']
        vuln.cvss_vector  = xml.attributes['cvssVector'] if xml.attributes['cvssVector']
        vuln.cvss_score   = xml.attributes['cvssScore'].to_f if xml.attributes['cvssScore']
        vuln
      end

      def self.parse(xml)
        parse_attributes(xml)
      end
    end

    # Details for a vulnerability.
    #
    class VulnerabilityDetail < VulnerabilitySummary
      # The HTML Description of this vulnerability.
      attr_accessor :description
      # External References for this vulnerability.
      # Array containing (Reference)
      attr_accessor :references
      # The HTML Solution for this vulnerability.
      attr_accessor :solution

      def initialize(id, title, severity)
        @id         = id
        @title      = title
        @severity   = severity
        @references = []
      end

      def self.parse(xml)
        vuln             = parse_attributes(xml)
        vuln.description = REXML::XPath.first(xml, 'description').text
        vuln.solution    = REXML::XPath.first(xml, 'solution').text
        xml.elements.each('references/reference') do |ref|
          vuln.references << Reference.new(ref.attributes['source'], ref.text)
        end
        vuln
      end
    end

    # Reference information for a Vulnerability.
    #
    class Reference
      attr_reader :source
      attr_reader :reference

      def initialize(source, reference)
        @source    = source
        @reference = reference
      end
    end
  end

  # Vulnerability finding information pulled from AJAX requests.
  # Data uses a numeric, console-specific vuln ID, which may need to be
  # cross-referenced to the String ID to be used elsewhere.
  #
  class VulnFinding
    # Unique identifier of the vulnerability.
    attr_reader :id
    # Unique, console-specific identifier of the vulnerability.
    attr_reader :console_id
    # Vulnerability title.
    attr_reader :title
    attr_reader :cvss_score
    attr_reader :cvss_vector
    attr_reader :risk
    # Date this vulnerability was published.
    attr_reader :published
    attr_reader :severity
    # Number of instances of this vulnerabilty finding on an asset.
    attr_reader :instances
    # Main published exploit module against this vulnerability, if any.
    attr_reader :exploit
    # Whether known malware kits exploit this vulnerability.
    attr_reader :malware
    # Date that a vuln was verified, if validation has been carried out.
    attr_reader :verified

    def initialize(json)
      @id          = json['nexVulnID']
      @console_id  = json['vulnID']
      @title       = json['title']
      @cvss_vector = json['cvssBase']
      @cvss_score  = json['cvssScore']
      @risk        = json['riskScore']
      @published   = Time.at(json['publishedDate'] / 1000)
      @severity    = json['severity']
      @instances   = json['vulnInstanceCount']
      @exploit     = json['mainExploit']
      @malware     = json['malwareCount']
      @verified    = DateTime.iso8601(json['verifiedDate'].slice(0, 15)).to_time if json['verifiedDate']
    end
  end

  # Vulnerability synopsis information pulled from AJAX requests.
  # Data uses a numeric, console-specific vuln ID, which may need to be
  # cross-referenced to the String ID to be used elsewhere.
  #
  class VulnSynopsis < VulnFinding
    def initialize(hash)
      @id          = hash['Vuln ID'].to_i
      @title       = hash['Vulnerability']
      @cvss_vector = hash['CVSS Base Vector']
      @cvss_score  = hash['CVSS Score'].to_f
      @risk        = hash['Risk'].to_f
      @published   = Time.at(hash['Published On'].to_i / 1000)
      @severity    = hash['Severity'].to_i
      @instances   = hash['Instances'].to_i
      @exploit     = hash['ExploitSource']
      @malware     = hash['MalwareSource'] == 'true'
    end
  end

  # A vulnerability discovered on an asset.
  #
  class Vulnerability < APIObject
    # Unique identifier of the vulnerability.
    attr_reader :id
    # Vulnerability title.
    attr_reader :title
    # Full vulnerability definition. [Lazy]
    attr_reader :vulnerability_definition
  end

  # An instance of a vulnerability discovered on an asset.
  # Accessible from {Nexpose::Asset#vulnerability_instances}.
  #
  class VulnerabilityInstance < APIObject
    # ID of the asset where the vulnerability instance was detected.
    attr_reader :asset_id
    # IP Address of the asset where the vulnerability instance was detected.
    attr_reader :asset_ip_address
    # ID of the scan where the vulnerability instance was detected.
    attr_reader :scan_id
    # The ID (natural key) of the vulnerability.
    attr_reader :vulnerability_id
    # The time at which the vulnerability test was performed.
    attr_reader :date
    # The vulnerable status of the vulnerability.
    attr_reader :status
    # The proof which explains why the vulnerability is present on the asset.
    # The value is often HTML-formatted text.
    attr_reader :proof
    # Key that can distinguish the instances of the same type on the system.
    # For spider vulnerabilities, this is typically the relative URI where the
    # vuln was discovered.
    attr_reader :key
    # The service that the vulnerability test was performed against.
    attr_reader :service
    # The port on which the service was running if the vulnerability was found
    # through a network service, -1 if not defined.
    attr_reader :port
    # Protocol the service was providing on which the vulnerability was found.
    attr_reader :protocol
  end
end
