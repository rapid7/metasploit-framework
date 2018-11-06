module Nexpose
  class Connection
    # Retrieve all vulnerability definitions currently in a Nexpose console.
    #
    # Note, this can easily take 30 seconds to complete and will load over
    # 55,000 vulnerability definitions.
    #
    # @return [Array[VulnerabilityDefinition]] Collection of vulnerability definitions.
    #
    def all_vulns
      uri  = '/api/2.0/vulnerability_definitions'
      resp = AJAX.get(self, uri, AJAX::CONTENT_TYPE::JSON, per_page: 2_147_483_647)
      json = JSON.parse(resp, symbolize_names: true)
      json[:resources].map { |e| VulnerabilityDefinition.new.object_from_hash(self, e) }
    end

    # Search for any vulnerability definitions which refer to a given CVE.
    #
    # @param [String] cve A valid CVE.
    # @return [Array[VulnerabilityDefinition]] A list of vuln definitions which check the CVE.
    #
    def find_vulns_by_cve(cve)
      uri  = '/api/2.0/vulnerability_definitions'
      resp = AJAX.get(self, uri, AJAX::CONTENT_TYPE::JSON, cve: cve)
      json = JSON.parse(resp, symbolize_names: true)
      json[:resources].map { |e| VulnerabilityDefinition.new.object_from_hash(self, e) }
    end

    # Search for any vulnerability definitions which refer to a given reference
    # ID.
    #
    # Examples:
    #   find_vulns_by_ref('oval', 'OVAL10476')
    #   find_vulns_by_ref('bid', 35067)
    #   find_vulns_by_ref('secunia', 35188)
    #
    # @param [String] source External vulnerability reference source.
    # @param [String] id Unique vulnerability reference ID.
    # @return [Array[VulnerabilityDefinition]] A list of vuln definitions which
    #   check the vulnerability.
    #
    def find_vulns_by_ref(source, id)
      uri  = '/api/2.0/vulnerability_definitions'
      resp = AJAX.get(self,
                      uri,
                      AJAX::CONTENT_TYPE::JSON,
                      source: source, id: id)
      json = JSON.parse(resp, symbolize_names: true)
      json[:resources].map { |e| VulnerabilityDefinition.new.object_from_hash(self, e) }
    end

    # Search for any vulnerability definitions which refer to a given title.
    #
    # Note: This method will return a maximum of 500 results. If the search
    # yields a high number of results, consider add more specific words to
    # the title.
    #
    # @param [String] title A (partial) title to search for.
    # @param [Boolean] all_words Whether to include all words from the search
    #   phrase in the search.
    # @return [Array[VulnerabilityDefinition]] A list of vuln definitions with titles matching
    #   the provided value.
    #
    def find_vulns_by_title(title, all_words = true)
      uri    = '/api/2.0/vulnerability_definitions'
      params = { title: title, all_words: all_words }
      resp   = AJAX.get(self, uri, AJAX::CONTENT_TYPE::JSON, params)
      json   = JSON.parse(resp, symbolize_names: true)
      json[:resources].map { |e| VulnerabilityDefinition.new.object_from_hash(self, e) }
    end
  end

  # Vulnerability definition object. Represents a known vulnerability on a given
  # Nexpose console.
  #
  class VulnerabilityDefinition < APIObject
    # Unique identifier of a vulnerability definition.
    attr_reader :id
    # Vulnerability title.
    attr_reader :title
    # Vulnerability description, usually formated in HTML.
    attr_reader :description
    # The CVEs for the vulnerability.
    attr_reader :cves
    # Date the vulnerability was publicized by the third-party, vendor, or another
    # authoring source.
    attr_reader :date_published
    # Date the vulnerability was first checked by Nexpose.
    attr_reader :date_added
    # Severity category. One of: Critical, Severe, Moderate.
    attr_reader :severity
    # Severity score, in the range of 0.0 to 10.0.
    attr_reader :severity_score
    # Risk score associated with vulnerability.
    attr_reader :riskscore

    # Whether the presence of the vulnerability can cause PCI failure.
    # One of: Pass, Fail.
    attr_reader :pci_status
    # PCI severity score of the vulnerability, measured on a scale of 1 to 5.
    attr_reader :pci_severity_score

    # CVSS score of the vulnerability. Value between 0.0 and 10.0.
    attr_reader :cvss_score
    # Full CVSS vector in CVSS Version 2.0 notation.
    attr_reader :cvss_vector
    # Base score for the exploitability of a vulnerability that is used to compute
    # the overall CVSS score.
    attr_reader :cvss_exploit_score
    # Base score for the impact of a vulnerability that is used to compute the
    # overall CVSS score.
    attr_reader :cvss_impact_score

    # Whether the vulnerability is classified as a denial-of-service vuln.
    attr_reader :denial_of_service

    # Load a vulnerability definition from the provided console.
    #
    # @param [Connection] nsc Active connection to a Nexpose console.
    # @param [String] id Unique identifier of a vulnerability definition.
    # @return [VulnerabilityDefinition] The requested vulnerability definition, if found.
    #
    def self.load(nsc, id)
      uri  = "/api/2.0/vulnerability_definitions/#{id}"
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      hash = JSON.parse(resp, symbolize_names: true)
      new.object_from_hash(nsc, hash)
    end
  end

  # Known malware kits that can target a vulnerability.
  #
  class MalwareKit < APIObject
    # Internal Nexpose identifier of the malware kit.
    attr_reader :id
    # Malware kit name.
    attr_reader :name
    # Malware kit description, if available.
    attr_reader :description
    # Popularity of the malware kit, which identifies how common or accessible
    # it is. Values include: rare, uncommon, common, popular, occasional.
    attr_reader :popularity
  end

  # Known exploits of a vulnerability.
  #
  class Exploit < APIObject
    # Internal Nexpose identifier of the exploit.
    attr_reader :id
    # Exploit title.
    attr_reader :title
    # A description of the exploit, if available.
    attr_reader :description
    # Skill level required to use the exploit. One of: Expert, Intermediate,
    # Novice.
    attr_reader :skill_level
    # Source which defined and published the exploit, such as Metasploit or
    # Exploit Database.
    attr_reader :source
    # Reference key used by the publishing source to identify the exploit.
    attr_reader :source_key
  end

  # External vulnerability reference.
  #
  class Reference < APIObject
    # Internal Nexpose identifier of the reference.
    attr_reader :id
    # Reference value, such as the full CVE identifier.
    attr_reader :reference
    # Reference source, such as CVE, MS, RedHat, etc.
    attr_reader :source
  end
end
