# -*- coding: binary -*-
require 'rexml/document'
require 'rex/ui'

module Rex
module Parser


class IP360ASPLXMLStreamParser

  @vulnid = nil
  @appid = nil
  @location = nil

  attr_accessor :on_found_aspl

  def initialize(&block)
    reset_state
    on_found_aspl = block if block
  end

  def reset_state
    @aspl = {'vulns' => {'name' => { }, 'cve' => { }, 'bid' => { } },
      'oses' => {'name' => { } } }
    @state = :generic_state
  end

  def tag_start(name, attributes)
    case name
    when "vulns"
      @location = "vulns"
    when "vuln"
      @vulnid = attributes['id'].strip
    when "name"
      @state = :is_name
    when "advisories"
      @c = ""
      @cfirst = 1
      @b = ""
      @bfirst = 1
      @x = Hash.new
    when "publisher"
      @state = :is_pub
    when "id"
      @state = :is_refid
    when "operatingSystems"
      @location = "os"
    when "operatingSystem"
      @osid = attributes['id'].strip
    end
  end

  def text(str)
    case @state
    when :is_name
      @aspl['vulns']['name'][@vulnid] = str if @location == "vulns"
      @aspl['oses'][@osid] = str if @location == "os"
    when :is_pub
      @x['pub'] = str
    when :is_refid
      @x['refid'] = str
    end
  end

  def tag_end(name)
    case name
    when "ontology"
      on_found_aspl.call(@aspl) if on_found_aspl
      reset_state
    when "advisory"
      if (@x['pub'] =~ /CVE/)
        if (@cfirst == 0)
          @c += ","
        end
        @c += @x['refid']
        @cfirst = 0
      elsif (@x['pub'] =~ /BugTraq/)
        if (@bfirst == 0)
          @b += ","
        end
        @b += @x['refid']
        @bfirst = 0
      end
    when "advisories"
      @aspl['vulns']['cve'][@vulnid] = @c
      @aspl['vulns']['bid'][@vulnid] = @b
      @c = ""
      @b = ""
    end
    @state = :generic_state
  end

  # We don't need these methods, but they're necessary to keep REXML happy
  #
  def xmldecl(version, encoding, standalone); end
  def cdata; end
  def comment(str); end
  def instruction(name, instruction); end
  def attlist; end
end

end
end
