# -*- coding: binary -*-
require 'rexml/document'
require 'rex/ui'

module Rex
module Parser


class IP360XMLStreamParser

  attr_accessor :on_found_host

  def initialize(&block)
    reset_state
    on_found_host = block if block
  end

  def reset_state
    @host = {'hname' => nil, 'hid' => nil, 'addr' => nil, 'mac' => nil, 'os' => nil,
      'vulns' => ['vuln' => {'vulnid' => nil, 'port' => nil, 'proto' => nil} ],
      'apps' => ['app' => {'appid' => nil, 'svcid' => nil, 'port' => nil, 'proto' => nil } ],
    }
    @state = :generic_state
  end

  def tag_start(name, attributes)
    case name
    when "host"
      @host['hid'] = attributes['persistent_id']
    when "ip"
      @state = :is_ip
    when "dnsName"
      @state = :is_fqdn
    when "macAddress"
      @state = :is_mac
    when "os"
      @host['os'] = attributes['id']
    when "vulnerability"
      @x = Hash.new
      @x['vulnid'] = attributes['id']
    when "port"
      @state = :is_port
    when "protocol"
      @state = :is_proto
    when "application"
      @y = Hash.new
      @y['appid'] = attributes['application_id']
      @y['svcid'] = attributes['svcid']
      @y['port'] = attributes['port']
      @y['proto'] = attributes['protocol']
      @host['apps'].push @y
    end
  end

  def text(str)
    case @state
    when :is_fqdn
      @host['hname'] = str
    when :is_ip
      @host['addr'] = str
    when :is_mac
      @host['mac'] = str
    when :is_port
      @x['port'] = str
    when :is_proto
      @x['proto'] = str
    end
  end

  def tag_end(name)
    case name
    when "host"
      on_found_host.call(@host) if on_found_host
      reset_state
    when "vulnerability"
      @host['vulns'].push @x
    end
    @state = :generic_state
  end

  def cdata(d)
    #do nothing
  end

  # We don't need these methods, but they're necessary to keep REXML happy
  #
  def xmldecl(version, encoding, standalone) # :nodoc:
  end
  def comment(str) # :nodoc:
  end
  def instruction(name, instruction) # :nodoc:
  end
  def attlist # :nodoc:
  end
end

end
end
