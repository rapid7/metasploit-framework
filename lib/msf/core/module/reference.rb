# -*- coding: binary -*-

###
#
# A reference to some sort of information.  This is typically a URL, but could
# be any type of referential value that people could use to research a topic.
#
###
class Msf::Module::Reference

  #
  # Serialize a reference from a string.
  #
  def self.from_s(str)
    return self.new(str)
  end

  #
  # Initializes a reference from a string.
  #
  def initialize(in_str)
    self.str = in_str
  end

  #
  # Compares references to see if they're equal.
  #
  def ==(tgt)
    return (tgt.to_s == to_s)
  end

  #
  # Returns the reference as a string.
  #
  def to_s
    return self.str
  end

  #
  # Serializes the reference instance from a string.
  #
  def from_s(in_str)
    self.str = in_str
  end

  #
  # The reference string.
  #
  attr_reader :str

protected

  attr_writer :str # :nodoc:

end

###
#
# A reference to a website.
#
###
class Msf::Module::SiteReference < Msf::Module::Reference

  #
  # Class method that translates a URL into a site reference instance.
  #
  def self.from_s(str)
    instance = self.new

    if (instance.from_s(str) == false)
      return nil
    end

    return instance
  end

  #
  # Initializes a site reference from an array.  ary[0] is the site and
  # ary[1] is the site context identifier, such as CVE.
  #
  def self.from_a(ary)
    return nil if (ary.length < 2)

    self.new(ary[0], ary[1])
  end

  #
  # Initialize the site reference.
  # If you're updating the references, please also update:
  # * tools/module_reference.rb
  # * https://docs.metasploit.com/docs/development/developing-modules/module-metadata/module-reference-identifiers.html
  #
  def initialize(in_ctx_id = 'Unknown', in_ctx_val = '')
    self.ctx_id  = in_ctx_id
    self.ctx_val = in_ctx_val

    if in_ctx_id == 'CVE'
      self.site = "https://nvd.nist.gov/vuln/detail/CVE-#{in_ctx_val}"
    elsif in_ctx_id == 'CWE'
      self.site = "https://cwe.mitre.org/data/definitions/#{in_ctx_val}.html"
    elsif in_ctx_id == 'BID'
      self.site = "http://www.securityfocus.com/bid/#{in_ctx_val}"
    elsif in_ctx_id == 'MSB'
      year = in_ctx_val[2..3]
      century = year[0] == '9' ? '19' : '20'
      self.site = "https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/#{century}#{year}/#{in_ctx_val}"
    elsif in_ctx_id == 'EDB'
      self.site = "https://www.exploit-db.com/exploits/#{in_ctx_val}"
    elsif in_ctx_id == 'US-CERT-VU'
      self.site = "https://www.kb.cert.org/vuls/id/#{in_ctx_val}"
    elsif in_ctx_id == 'ZDI'
      self.site = "http://www.zerodayinitiative.com/advisories/ZDI-#{in_ctx_val}"
    elsif in_ctx_id == 'WPVDB'
      self.site = "https://wpscan.com/vulnerability/#{in_ctx_val}"
    elsif in_ctx_id == 'PACKETSTORM'
      self.site = "https://packetstormsecurity.com/files/#{in_ctx_val}"
    elsif in_ctx_id == 'URL'
      self.site = in_ctx_val.to_s
    elsif in_ctx_id == 'LOGO'
      self.site = "Logo: #{in_ctx_val}"
    elsif in_ctx_id == 'SOUNDTRACK'
      self.site = "Soundtrack: #{in_ctx_val}"
    else
      self.site  = in_ctx_id
      self.site += " (#{in_ctx_val})" if (in_ctx_val)
    end
  end

  #
  # Returns the absolute site URL.
  #
  def to_s
    return site || ''
  end

  #
  # Serializes a site URL string.
  #
  def from_s(str)
    if (/(http:\/\/|https:\/\/|ftp:\/\/)/.match(str))
      self.site = str
      self.ctx_id  = 'URL'
      self.ctx_val = self.site
    else
      return false
    end

    return true
  end

  #
  # The site being referenced.
  #
  attr_reader :site
  #
  # The context identifier of the site, such as CVE.
  #
  attr_reader :ctx_id
  #
  # The context value of the reference, such as MS02-039
  #
  attr_reader :ctx_val

protected

  attr_writer :site, :ctx_id, :ctx_val

end
