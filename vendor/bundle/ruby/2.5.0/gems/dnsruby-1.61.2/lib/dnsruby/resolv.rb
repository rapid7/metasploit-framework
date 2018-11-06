# The Resolv class can be used to resolve addresses using /etc/hosts and /etc/resolv.conf,
# 
# The DNS class may be used to perform more queries. If greater control over the sending
# of packets is required, then the Resolver or SingleResolver classes may be used.
module Dnsruby


# NOTE!  Beware, there is a Ruby library class named Resolv, and you may need to
# explicitly specify Dnsruby::Resolv to use the Dnsruby Resolv class,
# even if you have include'd Dnsruby.

class Resolv

  # Address RegExp to use for matching IP addresses
  ADDRESS_REGEX = /(?:#{IPv4::Regex})|(?:#{IPv6::Regex})/


  # Some class methods require the use of an instance to compute their result.
  # For this purpose we create a single instance that can be reused.
  def self.instance
    @instance ||= self.new
  end


  # Class methods that delegate to instance methods:

  # Looks up the first IP address for +name+
  def self.getaddress(name)
    instance.getaddress(name)
  end

  # Looks up all IP addresses for +name+
  def self.getaddresses(name)
    instance.getaddresses(name)
  end

  # Iterates over all IP addresses for +name+
  def self.each_address(name, &block)
    instance.each_address(name, &block)
  end

  # Looks up the first hostname of +address+
  def self.getname(address)
    instance.getname(address)
  end

  # Looks up all hostnames of +address+
  def self.getnames(address)
    instance.getnames(address)
  end

  # Iterates over all hostnames of +address+
  def self.each_name(address, &proc)
    instance.each_name(address, &proc)
  end


  # Instance Methods:

  # Creates a new Resolv using +resolvers+
  def initialize(resolvers=[Hosts.new, DNS.new])
    @resolvers = resolvers
  end

  # Looks up the first IP address for +name+
  def getaddress(name)
    addresses = getaddresses(name)
    if addresses.empty?
      raise ResolvError.new("no address for #{name}")
    else
      addresses.first
    end
  end

  # Looks up all IP addresses for +name+
  def getaddresses(name)
    return [name] if ADDRESS_REGEX.match(name)
    @resolvers.each do |resolver|
      addresses = []
      resolver.each_address(name) { |address| addresses << address }
      return addresses unless addresses.empty?
    end
    []
  end

  # Iterates over all IP addresses for +name+
  def each_address(name)
    getaddresses(name).each { |address| yield(address)}
  end

  # Looks up the first hostname of +address+
  def getname(address)
    names = getnames(address)
    if names.empty?
      raise ResolvError.new("no name for #{address}")
    else
      names.first
    end
  end

  # Looks up all hostnames of +address+
  def getnames(address)
    @resolvers.each do |resolver|
      names = []
      resolver.each_name(address) { |name| names << name }
      return names unless names.empty?
    end
    []
  end

  # Iterates over all hostnames of +address+
  def each_name(address)
    getnames(address).each { |address| yield(address) }
  end


  require 'dnsruby/cache'
  require 'dnsruby/DNS'
  require 'dnsruby/hosts'
  require 'dnsruby/message/message'
  require 'dnsruby/update'
  require 'dnsruby/zone_transfer'
  require 'dnsruby/dnssec'
  require 'dnsruby/zone_reader'

end
end
