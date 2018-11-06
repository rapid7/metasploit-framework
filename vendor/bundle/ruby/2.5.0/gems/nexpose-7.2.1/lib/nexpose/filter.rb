module Nexpose
  # Object that represents a connection to a Nexpose Security Console.
  class Connection
    # Perform an asset filter search that will locate assets matching the
    # provided conditions.
    #
    # For example, the following call will return assets with Java installed:
    #   nsc.filter(Search::Field::SOFTWARE, Search::Operator::CONTAINS, 'java')
    #
    # @param [String] field Constant from Search::Field
    # @param [String] operator Constant from Search::Operator
    # @param [String] value Search term or constant from Search::Value
    # @return [Array[FilteredAsset]] List of matching assets.
    #
    def filter(field, operator, value = '')
      criterion = Criterion.new(field, operator, value)
      criteria  = Criteria.new(criterion)
      search(criteria)
    end

    # Perform a search that will match the criteria provided.
    #
    # For example, the following call will return assets with Java and .NET:
    #   java_criterion = Criterion.new(Search::Field::SOFTWARE,
    #                                  Search::Operator::CONTAINS,
    #                                  'java')
    #   dot_net_criterion = Criterion.new(Search::Field::SOFTWARE,
    #                                     Search::Operator::CONTAINS,
    #                                     '.net')
    #   criteria = Criteria.new([java_criterion, dot_net_criterion])
    #   results = nsc.search(criteria)
    #
    # @param [Criteria] criteria Criteria search object.
    # @return [Array[FilteredAsset]] List of matching assets.
    #
    def search(criteria)
      results = DataTable._get_json_table(self, '/data/asset/filterAssets', criteria._to_payload)
      results.map { |a| FilteredAsset.new(a) }
    end
  end

  # Constants for performing Asset Filter searches and generating Dynamic Asset
  # Groups.
  #
  module Search
    module_function

    # Search constants

    # Only these values are accepted for a field value.
    #
    module Field
      # Search for an Asset by name.
      # Valid Operators: IS, IS_NOT, STARTS_WITH, ENDS_WITH, CONTAINS, NOT_CONTAINS
      ASSET = 'ASSET'

      # Search for an Asset by CVE ID
      # Valid Operators: IS, IS_NOT, CONTAINS, NOT_CONTAINS
      CVE_ID = 'CVE_ID'

      # Valid Operators: IS, IS_NOT
      # Valid Values (See Value::AccessComplexity): LOW, MEDIUM, HIGH
      CVSS_ACCESS_COMPLEXITY = 'CVSS_ACCESS_COMPLEXITY'

      # Valid Operators: IS, IS_NOT
      # Valid Values (See Value::AccessVector): LOCAL, ADJACENT, NETWORK
      CVSS_ACCESS_VECTOR = 'CVSS_ACCESS_VECTOR'

      # Valid Operators: IS, IS_NOT
      # Valid Values (See Value::AuthenticationRequired): NONE, SINGLE, MULTIPLE
      CVSS_AUTHENTICATION_REQUIRED = 'CVSS_AUTHENTICATION_REQUIRED'

      # Valid Operators: IS, IS_NOT
      # Valid Values (See Value::CVSSImpact): NONE, PARTIAL, COMPLETE
      CVSS_AVAILABILITY_IMPACT = 'CVSS_AVAILABILITY_IMPACT'

      # Valid Operators: IS, IS_NOT
      # Valid Values (See Value::CVSSImpact): NONE, PARTIAL, COMPLETE
      CVSS_CONFIDENTIALITY_IMPACT = 'CVSS_CONFIDENTIALITY_IMPACT'

      # Valid Operators: IS, IS_NOT
      # Valid Values (See Value::CVSSImpact): NONE, PARTIAL, COMPLETE
      CVSS_INTEGRITY_IMPACT = 'CVSS_INTEGRITY_IMPACT'

      # Valid Operators: IS, IS_NOT, IN_RANGE, GREATER_THAN, LESS_THAN
      # Valid Values: Floats from 0.0 to 10.0
      CVSS_SCORE = 'CVSS_SCORE'

      # Valid Operators: IN, NOT_IN
      # Valid Values (See Value::HostType): UNKNOWN, VIRTUAL, HYPERVISOR, BARE_METAL
      HOST_TYPE = 'HOST_TYPE'

      # Valid Operators: IN, NOT_IN
      # Valid Values (See Value::IPType): IPv4, IPv6
      IP_ADDRESS_TYPE = 'IP_ADDRESS_TYPE'

      # Valid Operators: IN
      # Valid Values (See Value::IPType): IPv4, IPv6
      IP_ALT_ADDRESS_TYPE = 'IP_ALT_ADDRESS_TYPE'

      # Valid Operators: IS, IS_NOT, IN_RANGE, NOT_IN_RANGE, IN, NOT_IN, LIKE, NOT_LIKE
      IP_ADDRESS = 'IP_RANGE'
      IP_RANGE = IP_ADDRESS

      # Valid Operators: IS, IS_NOT, IN_RANGE
      # Valid Values: Integers from 1 to 65535
      OPEN_PORT = 'OPEN_PORT'

      # Valid Operators: CONTAINS, NOT_CONTAINS, IS_EMPTY, IS_NOT_EMPTY
      OS = 'OS'

      # Valid Operators: IS
      # Valid Values (See Value::PCICompliance): PASS, FAIL
      PCI_COMPLIANCE_STATUS = 'PCI_COMPLIANCE_STATUS'

      # Valid Operators: IS, IS_NOT, IN_RANGE, GREATER_THAN, LESS_THAN
      RISK_SCORE = 'RISK_SCORE'

      # Search based on the last scan date of an asset.
      # Valid Operators: ON_OR_BEFORE, ON_OR_AFTER, BETWEEN, EARLIER_THAN, WITHIN_THE_LAST
      # Valid Values: Use FixNum of days for EARLIER_THAN and WITHIN_THE_LAST.
      #               See Value::ScanDate::FORMAT for how to generate String
      #               values for all other arguments.
      SCAN_DATE = 'SCAN_DATE'

      # Valid Operators: CONTAINS, NOT_CONTAINS
      SERVICE = 'SERVICE'

      # Search based on the Site ID of an asset.
      # (Note that underlying search used Site ID, despite 'site name' value.)
      # Valid Operators: IN, NOT_IN
      # Valid Values: FixNum Site ID of the site.
      SITE_ID = 'SITE_NAME'

      # Valid Operators: CONTAINS, NOT_CONTAINS
      SOFTWARE = 'SOFTWARE'

      # Valid Operators: IS, IS_NOT, GREATER_THAN, LESS_THAN, IS_APPLIED, IS_NOT_APPLIED
      # Valid Values: VERY_HIGH, HIGH, NORMAL, LOW, VERY_LOW
      USER_ADDED_CRITICALITY_LEVEL = 'TAG_CRITICALITY'

      # Valid Operators: IS, IS_NOT, STARTS_WITH, ENDS_WITH, IS_APPLIED,
      #                  IS_NOT_APPLIED, CONTAINS, NOT_CONTAINS
      USER_ADDED_CUSTOM_TAG = 'TAG'

      # Valid Operators: IS, IS_NOT, STARTS_WITH, ENDS_WITH, IS_APPLIED,
      #                  IS_NOT_APPLIED, CONTAINS, NOT_CONTAINS
      USER_ADDED_TAG_LOCATION = 'TAG_LOCATION'

      # Valid Operators: IS, IS_NOT, STARTS_WITH, ENDS_WITH, IS_APPLIED,
      #                  IS_NOT_APPLIED, CONTAINS, NOT_CONTAINS
      USER_ADDED_TAG_OWNER = 'TAG_OWNER'

      # Valid Operators: ARE
      # Valid Values: PRESENT, NOT_PRESENT
      VALIDATED_VULNERABILITIES = 'VULNERABILITY_VALIDATED_STATUS'

      # Search against vulnerability titles that an asset contains.
      # Valid Operators: CONTAINS, NOT_CONTAINS
      VULNERABILITY = 'VULNERABILITY'

      # Valid Operators: INCLUDE, DO_NOT_INCLUDE
      # Valid Values (See Value::VulnerabilityExposure): MALWARE, METASPLOIT, DATABASE
      VULNERABILITY_EXPOSURES = 'VULNERABILITY_EXPOSURES'

      # Search by VULNERABILITY CATEGORY
      # Valid Operators: IS, IS_NOT, CONTAINS, NOT_CONTAINS, STARTS_WITH, ENDS_WITH
      VULN_CATEGORY = 'VULN_CATEGORY'
    end

    # List of acceptable operators. Not all fields accept all operators.
    #
    module Operator
      ARE             = 'ARE'
      BETWEEN         = 'BETWEEN'
      CONTAINS        = 'CONTAINS'
      DO_NOT_INCLUDE  = 'DO_NOT_INCLUDE'
      EARLIER_THAN    = 'EARLIER_THAN'
      ENDS_WITH       = 'ENDS_WITH'
      GREATER_THAN    = 'GREATER_THAN'
      IN              = 'IN'
      INCLUDE         = 'INCLUDE'
      IN_RANGE        = 'IN_RANGE'
      IS              = 'IS'
      IS_APPLIED      = 'IS_APPLIED'
      IS_EMPTY        = 'IS_EMPTY'
      IS_NOT          = 'IS_NOT'
      IS_NOT_APPLIED  = 'IS_NOT_APPLIED'
      IS_NOT_EMPTY    = 'IS_NOT_EMPTY'
      LESS_THAN       = 'LESS_THAN'
      LIKE            = 'LIKE'
      NOT_CONTAINS    = 'NOT_CONTAINS'
      NOT_IN          = 'NOT_IN'
      NOT_IN_RANGE    = 'NOT_IN_RANGE'
      NOT_LIKE        = 'NOT_LIKE'
      ON_OR_AFTER     = 'ON_OR_AFTER'
      ON_OR_BEFORE    = 'ON_OR_BEFORE'
      STARTS_WITH     = 'STARTS_WITH'
      WITHIN_THE_LAST = 'WITHIN_THE_LAST'
    end

    # Specialized values used by certain search fields
    #
    module Value
      # Constants for filtering on access complexity.
      module AccessComplexity
        LOW    = 'L'
        MEDIUM = 'M'
        HIGH   = 'H'
      end

      # Constants for filtering on access vector.
      module AccessVector
        LOCAL    = 'L'
        ADJACENT = 'A'
        NETWORK  = 'N'
      end

      # Constants for filtering on whether authentication is required.
      module AuthenticationRequired
        NONE     = 'N'
        SINGLE   = 'S'
        MULTIPLE = 'M'
      end

      # Constants for filtering on CVSS impact.
      module CVSSImpact
        NONE     = 'N'
        PARTIAL  = 'P'
        COMPLETE = 'C'
      end

      # Constants for filtering on host type.
      module HostType
        UNKNOWN    = '0'
        VIRTUAL    = '1'
        HYPERVISOR = '2'
        BARE_METAL = '3'
      end

      # Constants for filtering on IP type.
      module IPType
        IPv4 = '0'
        IPv6 = '1'
      end

      # Constants for filtering on PCI compliance.
      module PCICompliance
        PASS = '1'
        FAIL = '0'
      end

      # Constants for filtering on scan date.
      module ScanDate
        # Pass this format to #strftime() to get expected format for requests.
        # For example:
        # Time.now().strftime(Nexpose::Search::Value::ScanDate::FORMAT)
        FORMAT = '%m/%d/%Y'
      end

      # Constants for filtering on vulnerability validations.
      module ValidatedVulnerability
        NOT_PRESENT = 1
        PRESENT     = 0
      end

      # Constants for filtering on vulnerability exposure.
      module VulnerabilityExposure
        MALWARE    = 'type:"malware_type", name:"malwarekit"'
        # TODO: A problem in Nexpose causes these values to not be constant.
        METASPLOIT = 'type:"exploit_source_type", name:"2"'
        DATABASE   = 'type:"exploit_source_type", name:"1"'
      end
    end
  end

  # Individual search criterion.
  #
  class Criterion
    # Search field. One of Nexpose::Search::Field
    # @see Nexpose::Search::Field for any restrictions on the other attibutes.
    attr_accessor :field
    # Search operator. One of Nexpose::Search::Operator
    attr_accessor :operator
    # Search value. A search string or one of Nexpose::Search::Value
    attr_accessor :value

    def initialize(field, operator, value = '')
      @field    = field.upcase
      @operator = operator.upcase
      if value.is_a? Array
        @value = value.map(&:to_s)
      else
        @value = value.to_s
      end
    end

    # Convert this object into the map format expected by Nexpose.
    #
    def to_h
      { 'metadata' => { 'fieldName' => field },
        'operator' => operator,
        'values' => Array(value) }
    end

    def self.parse(json)
      Criterion.new(json['metadata']['fieldName'],
                    json['operator'],
                    json['values'])
    end
  end

  # Join search criteria for an asset filter search or dynamic asset group.
  #
  class Criteria
    # Whether to match any or all filters. One of 'OR' or 'AND'.
    attr_accessor :match
    # Array of criteria to match against.
    attr_accessor :criteria

    def initialize(criteria = [], match = 'AND')
      @criteria = Array(criteria)
      @match = match.upcase
    end

    def to_h
      { 'operator' => @match,
        'criteria' => @criteria.map(&:to_h) }
    end

    # Convert this object into the format expected by Nexpose.
    #
    def to_json
      JSON.generate(to_h)
    end

    # Generate the payload needed for a POST request for Asset Filter.
    #
    def _to_payload
      { 'dir' => -1,
        'results' => -1,
        'sort' => 'assetIP',
        'startIndex' => -1,
        'table-id' => 'assetfilter',
        'searchCriteria' => to_json }
    end

    def <<(criterion)
      criteria << criterion
    end

    def self.parse(json)
      # The call returns empty JSON, so default to 'AND' if not present.
      operator = json['operator'] || 'AND'
      ret = Criteria.new([], operator)
      json['criteria'].each do |c|
        ret.criteria << Criterion.parse(c)
      end
      ret
    end
  end

  # Asset data as returned by an Asset Filter search.
  #
  class FilteredAsset
    # Unique identifier of this asset. Also known as device ID.
    attr_reader :id

    attr_reader :ip
    attr_reader :name
    attr_reader :os

    attr_reader :exploit_count
    attr_reader :malware_count
    attr_reader :vuln_count
    attr_reader :risk_score

    # The first Site ID returned for this asset.
    # Not recommended if Asset Linking feature is enabled.
    attr_reader :site_id
    # Array of Site IDs for the asset. Use when Asset Linking is enabled.
    attr_reader :site_ids
    attr_reader :last_scan

    def initialize(json)
      @id            = json['assetID']
      @ip            = json['assetIP']
      @name          = json['assetName']
      @os            = json['assetOSName']
      @exploit_count = json['exploitCount'].to_i
      @malware_count = json['malwareCount'].to_i
      @vuln_count    = json['vulnCount'].to_i
      @risk_score    = json['riskScore'].to_f
      @site_ids      = json['sitePermissions'].map { |site| site['siteID'] }
      @site_id       = @site_ids.first
      @last_scan     = Time.at(json['lastScanDate'].to_i / 1000)
    end
  end
end
