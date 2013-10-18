require "rex/parser/nokogiri_doc_mixin"

module Rex
module Parser

load_nokogiri && class Outpost24Document < Nokogiri::XML::SAX::Document

  include NokogiriDocMixin

  def start_element(name, attrs)
    @state[:current_tag][name] = true
    case name
    when "hostlist"
      record_hosts
    when "portlist"
      record_services
    when "detaillist"
      record_vulns
    when "host"
      return unless in_tag("hostlist")
      record_host
    when "portinfo"
      return unless in_tag("portlist")
      return unless in_tag("portlist-host")
      record_service
    when "detail"
      return unless in_tag("detaillist")
      record_vuln
    when "report", "ip"
      record_text
    when "name"
      return unless in_tag("hostlist") || in_tag("detaillist")
      return unless in_tag("host") || in_tag("detail")
      record_text
    when "platform"
      return unless in_tag("hostlist")
      return unless in_tag("host")
      record_text
    when "portnumber", "protocol", "service"
      return unless in_tag("portlist")
      return unless in_tag("portlist-host")
      return unless in_tag("portinfo")
      record_text
    when "description", "information"
      return unless in_tag("detaillist")
      return unless in_tag("detail")
      record_text
    when "id"
      return unless in_tag("detaillist")
      return unless in_tag("detail")
      return unless in_tag("cve")
      record_text
    end
  end

  def end_element(name)
    case name
    when "hostlist"
      report_hosts
    when "portlist"
      report_services
    when "detaillist"
      report_vulns
    when "host"
      return unless in_tag("hostlist")
      collect_host
    when "portinfo"
      return unless in_tag("portlist")
      return unless in_tag("portlist-host")
      collect_service
    when "detail"
      return unless in_tag("detaillist")
      collect_vuln
    when "report"
      collect_product
    when "ip"
      collect_ip
    when "name"
      if in_tag("hostlist") && in_tag("host")
        collect_host_data(name)
      elsif in_tag("detaillist") && in_tag("detail")
        collect_vuln_data(name)
      end
    when "platform"
      return unless in_tag("hostlist")
      return unless in_tag("host")
      collect_host_data(name)
    when "portnumber", "protocol", "service"
      return unless in_tag("portlist")
      return unless in_tag("portlist-host")
      return unless in_tag("portinfo")
      collect_service_data(name)
    when "description", "information"
      return unless in_tag("detaillist")
      return unless in_tag("detail")
      collect_vuln_data(name)
    when "id"
      return unless in_tag("detaillist")
      return unless in_tag("detail")
      return unless in_tag("cve")
      collect_vuln_data(name)
    end
    @state[:current_tag].delete(name)
  end

  def record_hosts
    @report_data[:hosts] = []
  end

  def record_services
    @report_data[:services] = []
  end

  def record_vulns
    @report_data[:vulns] = []
  end

  def record_host
    @host = {}
  end

  def record_service
    @service = {}
  end

  def record_vuln
    @vuln = {}
    @refs = []
  end

  def record_text
    @state[:has_text] = true
  end

  def collect_host
    @host[:host] = @state[:host]
    @host[:name] = @state[:hname]
    @host[:os_name] = @state[:os_name]
    @host[:info] = @state[:pinfo]
    @report_data[:hosts] << @host
  end

  def collect_service
    @service[:host] = @state[:host]
    @service[:port] = @state[:port]
    @service[:proto] = @state[:proto]
    @service[:name] = @state[:sname]
    @service[:info] = @state[:pinfo]
    @report_data[:services] << @service
  end

  def collect_vuln
    @vuln[:host] = @state[:host]
    @vuln[:name] = @state[:vname]
    @vuln[:info] = @state[:vinfo]
    @vuln[:refs] = @refs
    @report_data[:vulns] << @vuln
  end

  def collect_product
    @state[:has_text] = false
    @state[:pinfo] = @text.strip if @text
    @text = nil
  end

  def collect_ip
    @state[:has_text] = false
    @state[:host] = @text.strip if @text
    @text = nil
  end

  def collect_host_data(name)
    @state[:has_text] = false
    if name == "name"
      @state[:hname] = @text.strip if @text
    elsif name == "platform"
      if @text
        @state[:os_name] = @text.strip
      else
        @state[:os_name] = Msf::OperatingSystems::UNKNOWN
      end
    end
    @text = nil
  end

  def collect_service_data(name)
    @state[:has_text] = false
    if name == "portnumber"
      @state[:port] = @text.strip if @text
    elsif name == "protocol"
      @state[:proto] = @text.strip.downcase if @text
    elsif name == "service"
      @state[:sname] = @text.strip if @text
    end
    @text = nil
  end

  def collect_vuln_data(name)
    @state[:has_text] = false
    if name == "name"
      @state[:vname] = @text.strip if @text
    elsif name == "description"
      @state[:vinfo] = @text.strip if @text
    elsif name == "information"
      @state[:vinfo] << " #{@text.strip if @text}"
    elsif name == "id"
      @state[:ref] = @text.strip if @text
      @refs << normalize_ref("CVE", @state[:ref])
    end
    @text = nil
  end

  def report_hosts
    block = @block
    @report_data[:hosts].each do |h|
      db.emit(:address, h[:host], &block) if block
      db_report(:host, h)
    end
  end

  def report_services
    block = @block
    @report_data[:services].each do |s|
      db.emit(:service, "#{s[:host]}:#{s[:port]}/#{s[:proto]}", &block) if block
      db_report(:service, s)
    end
  end

  def report_vulns
    block = @block
    @report_data[:vulns].each do |v|
      db.emit(:vuln, ["#{v[:name]} (#{v[:host]})", 1], &block) if block
      db_report(:vuln, v)
    end
  end

end
end
end
