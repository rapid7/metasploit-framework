# -*- coding: binary -*-
module Rex
module Parser


class NetSparkerXMLStreamParser

  attr_accessor :on_found_vuln

  def initialize(on_found_vuln = nil)
    self.on_found_vuln = on_found_vuln if on_found_vuln
    reset_state
  end

  def reset_state
    @state = :generic_state
    @vuln  = {'info' => []}
    @attr  = {}
  end

  def tag_start(name, attributes)
    @state = "in_#{name.downcase}".intern
    @attr  = attributes

    case name
    when "vulnerability"
      @vuln = { 'info' => [] }
      @vuln['confirmed'] = attributes['confirmed']
    end
  end

  def text(str)
    case @state
    when :in_url
      @vuln['url'] ||= ""
      @vuln['url']  += str
    when :in_type
      @vuln['type'] ||= ""
      @vuln['type']  += str
    when :in_severity
      @vuln['severity'] ||= ""
      @vuln['severity']  += str
    when :in_vulnerableparametertype
      @vuln["vparam_type"] ||= ""
      @vuln["vparam_type"]  += str
    when :in_vulnerableparameter
      @vuln["vparam_name"] ||= ""
      @vuln["vparam_name"]  += str
    when :in_vulnerableparametervalue
      @vuln["vparam_value"] ||= ""
      @vuln["vparam_value"]  += str
    when :in_rawrequest
      @vuln["request"] ||= ""
      @vuln["request"]  += str
    when :in_rawresponse
      @vuln["response"] ||= ""
      @vuln["response"]  += str
    when :in_info
      # <info name="Identified Internal Path(s)">C:\AppServ\www\test-apps\dokeos\main\inc\banner.inc.php</info>
      if not str.to_s.strip.empty?
        @vuln['info'] << [@attr['name'] || "Information", str]
      end
    when :in_netsparker
    when :in_target
    when :in_scantime
    when :generic_state
    when :in_vulnerability
    when :in_extrainformation
    else
      # $stderr.puts "unknown state: #{@state}"
    end
  end

  def tag_end(name)
    case name
    when "vulnerability"
      @vuln.keys.each do |k|
        @vuln[k] = @vuln[k].strip if @vuln[k].kind_of?(::String)
      end
      on_found_vuln.call(@vuln) if on_found_vuln
      reset_state
    end
  end

  # We don't need these methods, but they're necessary to keep REXML happy
  def xmldecl(version, encoding, standalone); end
  def cdata(data)
    puts "cdata for #{@state} (#{data.length})"
    case @state
    when :in_rawresponse
      @vuln["response"] = data
    when :in_rawrequest
      @vuln["request"] = data
    when :in_info
      if not data.to_s.strip.empty?
        @vuln['info'] << [@attr['name'] || "Information", data]
      end
    end
  end

  def comment(str); end
  def instruction(name, instruction); end
  def attlist; end
end
end
end

__END__

