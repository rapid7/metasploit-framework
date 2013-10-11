require "rex/parser/nokogiri_doc_mixin"

module Rex
module Parser

load_nokogiri && class Outpost24Document < Nokogiri::XML::SAX::Document

  include NokogiriDocMixin

  def start_element(name, attrs)
    @state[:current_tag][name] = true
    case name
    when "hostlist"
      @report_data[:hosts] = []
    when "portlist"
      @report_data[:services] = []
    when "detaillist"
      @report_data[:vulns] = []
    when "host"
      return unless in_tag("hostlist")
      @host = {}
    when "portinfo"
      return unless in_tag("portlist")
      return unless in_tag("portlist-host")
      @service = {}
    when "detail"
      return unless in_tag("detaillist")
      @vuln = {}
    when "ip"
      @state[:has_text] = true
    when "platform"
      return unless in_tag("hostlist")
      return unless in_tag("host")
      @state[:has_text] = true
    when "portnumber", "protocol", "service"
      return unless in_tag("portlist")
      return unless in_tag("portlist-host")
      return unless in_tag("portinfo")
      @state[:has_text] = true
    when "name", "description"
      return unless in_tag("detaillist")
      return unless in_tag("detail")
      @state[:has_text] = true
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
    when "ip"
      collect_ip
    when "platform"
      return unless in_tag("hostlist")
      return unless in_tag("host")
      collect_host_data(name)
    when "portnumber", "protocol", "service"
      return unless in_tag("portlist")
      return unless in_tag("portlist-host")
      return unless in_tag("portinfo")
      collect_service_data(name)
    when "name", "description"
      return unless in_tag("detaillist")
      return unless in_tag("detail")
      collect_vuln_data(name)
    end
    @state[:current_tag].delete(name)
  end

  def collect_host
    @host[:host] = @state[:host]
    @host[:os_name] = @state[:os_name]
    @report_data[:hosts] << @host
  end

  def collect_service
    @service[:host] = @state[:host]
    @service[:port] = @state[:port]
    @service[:proto] = @state[:proto]
    @service[:name] = @state[:sname]
    @report_data[:services] << @service
  end

  def collect_vuln
    @vuln[:host] = @state[:host]
    @vuln[:name] = @state[:name]
    @vuln[:info] = @state[:info]
    @report_data[:vulns] << @vuln
  end

  def collect_ip
    @state[:has_text] = false
    @state[:host] = @text.strip if @text
    @text = nil
  end

  def collect_host_data(name)
    @state[:has_text] = false
    if name == "platform"
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
      @state[:name] = @text.strip if @text
    elsif name == "description"
      @state[:info] = @text.strip if @text
    end
    @text = nil
  end

  def report_hosts
    @report_data[:hosts].each do |host|
      db_report(:host, host)
    end
  end

  def report_services
    @report_data[:services].each do |service|
      db_report(:service, service)
    end
  end

  def report_vulns
    @report_data[:vulns].each do |vuln|
      db_report(:vuln, vuln)
    end
  end

end
end
end
