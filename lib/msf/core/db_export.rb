# -*- coding: binary -*-
module Msf

##
#
# This class provides export capabilities
#
##
class DBManager
class Export

  attr_accessor :workspace

  def initialize(workspace)
    self.workspace = workspace
  end

  def myworkspace
    self.workspace
  end

  def myusername
    @username ||= (ENV['LOGNAME'] || ENV['USERNAME'] || ENV['USER'] || "unknown").to_s.strip.gsub(/[^A-Za-z0-9\x20]/,"_")
  end

  # Hosts are always allowed. This is really just a stub.
  def host_allowed?(arg)
    true
  end

  # Creates the PWDUMP text file. smb_hash and ssh_key credentials are
  # treated specially -- all other ptypes are treated as plain text.
  #
  # Some day in the very near future, this file format will be importable --
  # the comment preceding the credential is always in the format of IPAddr:Port/Proto (name),
  # so it should be a simple matter to read them back in and store credentials
  # in the right place. Finally, this format is already parsable by John the Ripper,
  # so hashes can be bruteforced offline.
  def to_pwdump_file(path, &block)
    yield(:status, "start", "password dump") if block_given?
    creds = extract_credentials
    report_file = ::File.open(path, "wb")
    report_file.write "# Metasploit PWDump Export v1\n"
    report_file.write "# Generated: #{Time.now.utc}\n"
    report_file.write "# Project: #{myworkspace.name}\n"
    report_file.write "#\n"
    report_file.write "#" * 40; report_file.write "\n"

    count = count_credentials("smb_hash",creds)
    scount = creds.has_key?("smb_hash") ? creds["smb_hash"].size : 0
    yield(:status, "start", "LM/NTLM Hash dump") if block_given?
    report_file.write "# LM/NTLM Hashes (%d services, %d hashes)\n" % [scount, count]
    write_credentials("smb_hash",creds,report_file)

    count = count_credentials("smb_netv1_hash",creds)
    scount = creds.has_key?("smb_netv1_hash") ? creds["smb_netv1_hash"].size : 0
    yield(:status, "start", "NETLMv1/NETNTLMv1 Hash dump") if block_given?
    report_file.write "# NETLMv1/NETNTLMv1 Hashes (%d services, %d hashes)\n" % [scount, count]
    write_credentials("smb_netv1_hash",creds,report_file)

    count = count_credentials("smb_netv2_hash",creds)
    scount = creds.has_key?("smb_netv2_hash") ? creds["smb_netv2_hash"].size : 0
    yield(:status, "start", "NETLMv2/NETNTLMv2 Hash dump") if block_given?
    report_file.write "# NETLMv2/NETNTLMv2 Hashes (%d services, %d hashes)\n" % [scount, count]
    write_credentials("smb_netv2_hash",creds,report_file)

    count = count_credentials("ssh_key",creds)
    scount = creds.has_key?("ssh_key") ? creds["ssh_key"].size : 0
    yield(:status, "start", "SSH Key dump") if block_given?
    report_file.write "# SSH Private Keys (%d services, %d keys)\n" % [scount, count]
    write_credentials("ssh_key",creds,report_file)

    count = count_credentials("text",creds)
    scount = creds.has_key?("text") ? creds["text"].size : 0
    yield(:status, "start", "Plaintext Credential dump") if block_given?
    report_file.write "# Plaintext Credentials (%d services, %d credentials)\n" % [scount, count]
    write_credentials("text",creds,report_file)

    report_file.flush
    report_file.close
    yield(:status, "complete", "password dump") if block_given?
    true
  end

  # Counts the total number of credentials for its type.
  def count_credentials(ptype,creds)
    sz = 0
    if creds[ptype]
      creds[ptype].each_pair { |svc, data| data.each { |c| sz +=1 } }
    end
    return sz
  end

  # Formats credentials according to their type, and writes it out to the
  # supplied report file. Note for reimporting: Blank values are <BLANK>
  def write_credentials(ptype,creds,report_file)
    if creds[ptype]
      creds[ptype].each_pair do |svc, data|
        report_file.write "# #{svc}\n"
        case ptype
        when "smb_hash"
          data.each do |c|
            user = (c.user.nil? || c.user.empty?) ? "<BLANK>" : c.user
            pass = (c.pass.nil? || c.pass.empty?) ? "<BLANK>" : c.pass
            report_file.write "%s:%d:%s:::\n" % [user,c.id,pass]
          end
        when "smb_netv1_hash"
          data.each do |c|
            user = (c.user.nil? || c.user.empty?) ? "<BLANK>" : c.user
            pass = (c.pass.nil? || c.pass.empty?) ? "<BLANK>" : c.pass
            report_file.write "%s::%s\n" % [user,pass]
          end
        when "smb_netv2_hash"
          data.each do |c|
            user = (c.user.nil? || c.user.empty?) ? "<BLANK>" : c.user
            pass = (c.pass.nil? || c.pass.empty?) ? "<BLANK>" : c.pass
            if pass != "<BLANK>"
              pass = (c.pass.upcase =~ /^[\x20-\x7e]*:[A-F0-9]{48}:[A-F0-9]{50,}/m) ? c.pass : "<BLANK>"
            end
            if pass == "<BLANK>"
              # Basically this is an error (maybe around [\x20-\x7e] in regex) above
              report_file.write(user + "::" + pass + ":")
              report_file.write(pass + ":" +  pass + ":" + pass + "\n")
            else
              datas = pass.split(":")
              if datas[1] != "00" * 24
                report_file.write "# netlmv2\n"
                report_file.write(user + "::" + datas[0] + ":")
                report_file.write(datas[3] + ":" +  datas[1][0,32] + ":" + datas[1][32,16] + "\n")
              end
              report_file.write "# netntlmv2\n"
              report_file.write(user + "::" + datas[0] + ":")
              report_file.write(datas[3] + ":" +  datas[2][0,32] + ":" + datas[2][32..-1] + "\n")
            end
          end
        when "ssh_key"
          data.each do |c|
            if ::File.exists?(c.pass) && ::File.readable?(c.pass)
              user = (c.user.nil? || c.user.empty?) ? "<BLANK>" : c.user
              key = ::File.open(c.pass) {|f| f.read f.stat.size}
              key_id = (c.proof && c.proof[/^KEY=/]) ? c.proof[4,47] : "<NO-ID>"
              report_file.write "#{user} '#{key_id}'\n"
              report_file.write key
              report_file.write "\n" unless key[-1,1] == "\n"
            # Report file missing / permissions issues in the report itself.
            elsif !::File.exists?(c.pass)
              report_file.puts "Warning: missing private key file '#{c.pass}'."
            else
              report_file.puts "Warning: could not read the private key '#{c.pass}'."
            end
          end
        else "text"
          data.each do |c|
            user = (c.user.nil? || c.user.empty?) ? "<BLANK>" : Rex::Text.ascii_safe_hex(c.user, true)
            pass = (c.pass.nil? || c.pass.empty?) ? "<BLANK>" : Rex::Text.ascii_safe_hex(c.pass, true)
            report_file.write "%s %s\n" % [user,pass]
          end
        end
        report_file.flush
      end
    else
      report_file.write "# No credentials for this type were discovered.\n"
    end
    report_file.write "#" * 40; report_file.write "\n"
  end

  # Extracts credentials and organizes by type, then by host, and finally by individual
  # credential data. Will look something like:
  #
  #   {"smb_hash" => {"host1:445" => [user1,user2,user3], "host2:445" => [user4,user5]}},
  #   {"ssh_key" => {"host3:22" => [user10,user20]}},
  #   {"text" => {"host4:23" => [user100,user101]}}
  #
  # This hash of hashes of arrays is, in turn, consumed by gen_export_pwdump.
  def extract_credentials
    creds = Hash.new
    creds["ssh_key"] = {}
    creds["smb_hash"] = {}
    creds["text"] = {}
    myworkspace.each_cred do |cred|
      next unless host_allowed?(cred.service.host.address)
      # Skip anything that's not associated with a specific host and port
      next unless (cred.service && cred.service.host && cred.service.host.address && cred.service.port)
      # TODO: Toggle active/all
      next unless cred.active
      svc = "%s:%d/%s (%s)" % [cred.service.host.address,cred.service.port,cred.service.proto,cred.service.name]
      case cred.ptype
      when /^password/
        ptype = "text"
      else
        ptype = cred.ptype
      end
      creds[ptype] ||= {}
      creds[ptype][svc] ||= []
      creds[ptype][svc] << cred
    end
    return creds
  end


  def to_xml_file(path, &block)

    yield(:status, "start", "report") if block_given?
    extract_target_entries
    report_file = ::File.open(path, "wb")

    report_file.write %Q|<?xml version="1.0" encoding="UTF-8"?>\n|
    report_file.write %Q|<MetasploitV4>\n|
    report_file.write %Q|<generated time="#{Time.now.utc}" user="#{myusername}" project="#{myworkspace.name.gsub(/[^A-Za-z0-9\x20]/,"_")}" product="framework"/>\n|

    yield(:status, "start", "hosts") if block_given?
    report_file.write %Q|<hosts>\n|
    report_file.flush
    extract_host_info(report_file)
    report_file.write %Q|</hosts>\n|

    yield(:status, "start", "events") if block_given?
    report_file.write %Q|<events>\n|
    report_file.flush
    extract_event_info(report_file)
    report_file.write %Q|</events>\n|

    yield(:status, "start", "services") if block_given?
    report_file.write %Q|<services>\n|
    report_file.flush
    extract_service_info(report_file)
    report_file.write %Q|</services>\n|

    yield(:status, "start", "credentials") if block_given?
    report_file.write %Q|<credentials>\n|
    report_file.flush
    extract_credential_info(report_file)
    report_file.write %Q|</credentials>\n|

    yield(:status, "start", "web sites") if block_given?
    report_file.write %Q|<web_sites>\n|
    report_file.flush
    extract_web_site_info(report_file)
    report_file.write %Q|</web_sites>\n|

    yield(:status, "start", "web pages") if block_given?
    report_file.write %Q|<web_pages>\n|
    report_file.flush
    extract_web_page_info(report_file)
    report_file.write %Q|</web_pages>\n|

    yield(:status, "start", "web forms") if block_given?
    report_file.write %Q|<web_forms>\n|
    report_file.flush
    extract_web_form_info(report_file)
    report_file.write %Q|</web_forms>\n|

    yield(:status, "start", "web vulns") if block_given?
    report_file.write %Q|<web_vulns>\n|
    report_file.flush
    extract_web_vuln_info(report_file)
    report_file.write %Q|</web_vulns>\n|

    yield(:status, "start", "module details") if block_given?
    report_file.write %Q|<module_details>\n|
    report_file.flush
    extract_module_detail_info(report_file)
    report_file.write %Q|</module_details>\n|


    report_file.write %Q|</MetasploitV4>\n|
    report_file.flush
    report_file.close

    yield(:status, "complete", "report") if block_given?

    true
  end

  # A convenience function that bundles together host, event, and service extraction.
  def extract_target_entries
    extract_host_entries
    extract_event_entries
    extract_service_entries
    extract_credential_entries
    extract_note_entries
    extract_vuln_entries
    extract_web_entries
  end

  # Extracts all the hosts from a project, storing them in @hosts and @owned_hosts
  def extract_host_entries
    @owned_hosts = []
    @hosts = myworkspace.hosts
    @hosts.each do |host|
      if host.notes.find :first, :conditions => { :ntype => 'pro.system.compromise' }
        @owned_hosts << host
      end
    end
  end

  # Extracts all events from a project, storing them in @events
  def extract_event_entries
    @events = myworkspace.events.find :all, :order => 'created_at ASC'
  end

  # Extracts all services from a project, storing them in @services
  def extract_service_entries
    @services = myworkspace.services
  end

  # Extracts all credentials from a project, storing them in @creds
  def extract_credential_entries
    @creds = []
    myworkspace.each_cred {|cred| @creds << cred}
  end

  # Extracts all notes from a project, storing them in @notes
  def extract_note_entries
    @notes = myworkspace.notes
  end

  # Extracts all vulns from a project, storing them in @vulns
  def extract_vuln_entries
    @vulns = myworkspace.vulns
  end

  # Extract all web entries, storing them in instance variables
  def extract_web_entries
    @web_sites = myworkspace.web_sites
    @web_pages = myworkspace.web_pages
    @web_forms = myworkspace.web_forms
    @web_vulns = myworkspace.web_vulns
  end

  # Simple marshalling, for now. Can I use ActiveRecord::ConnectionAdapters::Quoting#quote
  # directly? Is it better to just marshal everything and destroy readability? Howabout
  # XML safety?
  def marshalize(obj)
    case obj
    when String
      obj.strip
    when TrueClass, FalseClass, Float, Fixnum, Bignum, Time
      obj.to_s.strip
    when BigDecimal
      obj.to_s("F")
    when NilClass
      "NULL"
    else
      [Marshal.dump(obj)].pack("m").gsub(/\s+/,"")
    end
  end

  def create_xml_element(key,value)
    tag = key.gsub("_","-")
    el = REXML::Element.new(tag)
    if value
      data = marshalize(value)
      data.force_encoding(Encoding::BINARY) if data.respond_to?('force_encoding')
      data.gsub!(/([\x00-\x08\x0b\x0c\x0e-\x1f\x80-\xFF])/){ |x| "\\x%.2x" % x.unpack("C*")[0] }
      el << REXML::Text.new(data)
    end
    return el
  end

  # @note there is no single root element output by
  #   {#extract_module_detail_info}, so if calling {#extract_module_detail_info}
  #   directly, it is the caller's responsibility to add an opening and closing
  #   tag to report_file around the call to {#extract_module_detail_info}.
  #
  # Writes a module_detail element to the report_file for each
  # Mdm::Module::Detail.
  #
  # @param report_file [#write, #flush] IO stream to which to write the
  #   module_detail elements.
  # @return [void]
  def extract_module_detail_info(report_file)
      Mdm::Module::Detail.all.each do |m|
      report_file.write("<module_detail>\n")
      m_id = m.attributes["id"]

      # Module attributes
      m.attributes.each_pair do |k,v|
        el = create_xml_element(k,v)
        report_file.write("    #{el}\n") # Not checking types
      end

      # Authors sub-elements
      # @todo https://www.pivotaltracker.com/story/show/48451001
      report_file.write("    <module_authors>\n")
      m.authors.find(:all).each do |d|
        d.attributes.each_pair do |k,v|
          el = create_xml_element(k,v)
          report_file.write("        #{el}\n")
        end
      end
      report_file.write("    </module_authors>\n")

      # Refs sub-elements
      # @todo https://www.pivotaltracker.com/story/show/48451001
      report_file.write("    <module_refs>\n")
      m.refs.find(:all).each do |d|
        d.attributes.each_pair do |k,v|
          el = create_xml_element(k,v)
          report_file.write("        #{el}\n")
        end
      end
      report_file.write("    </module_refs>\n")


      # Archs sub-elements
      # @todo https://www.pivotaltracker.com/story/show/48451001
      report_file.write("    <module_archs>\n")
      m.archs.find(:all).each do |d|
        d.attributes.each_pair do |k,v|
          el = create_xml_element(k,v)
          report_file.write("        #{el}\n")
        end
      end
      report_file.write("    </module_archs>\n")


      # Platforms sub-elements
      # @todo https://www.pivotaltracker.com/story/show/48451001
      report_file.write("    <module_platforms>\n")
      m.platforms.find(:all).each do |d|
        d.attributes.each_pair do |k,v|
          el = create_xml_element(k,v)
          report_file.write("        #{el}\n")
        end
      end
      report_file.write("    </module_platforms>\n")


      # Targets sub-elements
      # @todo https://www.pivotaltracker.com/story/show/48451001
      report_file.write("    <module_targets>\n")
      m.targets.find(:all).each do |d|
        d.attributes.each_pair do |k,v|
          el = create_xml_element(k,v)
          report_file.write("        #{el}\n")
        end
      end
      report_file.write("    </module_targets>\n")

      # Actions sub-elements
      # @todo https://www.pivotaltracker.com/story/show/48451001
      report_file.write("    <module_actions>\n")
      m.actions.find(:all).each do |d|
        d.attributes.each_pair do |k,v|
          el = create_xml_element(k,v)
          report_file.write("        #{el}\n")
        end
      end
      report_file.write("    </module_actions>\n")

      # Mixins sub-elements
      # @todo https://www.pivotaltracker.com/story/show/48451001
      report_file.write("    <module_mixins>\n")
      m.mixins.find(:all).each do |d|
        d.attributes.each_pair do |k,v|
          el = create_xml_element(k,v)
          report_file.write("        #{el}\n")
        end
      end
      report_file.write("    </module_mixins>\n")

      report_file.write("</module_detail>\n")
    end
    report_file.flush
  end

  # ActiveRecord's to_xml is easy and wrong. This isn't, on both counts.
  def extract_host_info(report_file)
    @hosts.each do |h|
      report_file.write("  <host>\n")
      host_id = h.attributes["id"]

      # Host attributes
      h.attributes.each_pair do |k,v|
        el = create_xml_element(k,v)
        report_file.write("    #{el}\n") # Not checking types
      end

      # Host details sub-elements
      report_file.write("    <host_details>\n")
      h.host_details.find(:all).each do |d|
        report_file.write("        <host_detail>\n")
        d.attributes.each_pair do |k,v|
          el = create_xml_element(k,v)
          report_file.write("            #{el}\n")
        end
        report_file.write("        </host_detail>\n")
      end
      report_file.write("    </host_details>\n")

      # Host exploit attempts sub-elements
      report_file.write("    <exploit_attempts>\n")
      h.exploit_attempts.find(:all).each do |d|
        report_file.write("        <exploit_attempt>\n")
        d.attributes.each_pair do |k,v|
          el = create_xml_element(k,v)
          report_file.write("            #{el}\n")
        end
        report_file.write("        </exploit_attempt>\n")
      end
      report_file.write("    </exploit_attempts>\n")

      # Service sub-elements
      report_file.write("    <services>\n")
      @services.find_all_by_host_id(host_id).each do |e|
        report_file.write("      <service>\n")
        e.attributes.each_pair do |k,v|
          el = create_xml_element(k,v)
          report_file.write("      #{el}\n")
        end
        report_file.write("      </service>\n")
      end
      report_file.write("    </services>\n")

      # Notes sub-elements
      report_file.write("    <notes>\n")
      @notes.find_all_by_host_id(host_id).each do |e|
        report_file.write("      <note>\n")
        e.attributes.each_pair do |k,v|
          el = create_xml_element(k,v)
          report_file.write("      #{el}\n")
        end
        report_file.write("      </note>\n")
      end
      report_file.write("    </notes>\n")

      # Vulns sub-elements
      report_file.write("    <vulns>\n")
      @vulns.find_all_by_host_id(host_id).each do |e|
        report_file.write("      <vuln>\n")
        e.attributes.each_pair do |k,v|
          el = create_xml_element(k,v)
          report_file.write("      #{el}\n")
        end

        # References
        report_file.write("        <refs>\n")
        e.refs.each do |ref|
          el = create_xml_element("ref",ref.name)
          report_file.write("          #{el}\n")
        end
        report_file.write("        </refs>\n")


        # Vuln details sub-elements
        report_file.write("            <vuln_details>\n")
        e.vuln_details.find(:all).each do |d|
          report_file.write("                <vuln_detail>\n")
          d.attributes.each_pair do |k,v|
            el = create_xml_element(k,v)
            report_file.write("                    #{el}\n")
          end
          report_file.write("                </vuln_detail>\n")
        end
        report_file.write("            </vuln_details>\n")


        # Vuln attempts sub-elements
        report_file.write("            <vuln_attempts>\n")
        e.vuln_attempts.find(:all).each do |d|
          report_file.write("                <vuln_attempt>\n")
          d.attributes.each_pair do |k,v|
            el = create_xml_element(k,v)
            report_file.write("                    #{el}\n")
          end
          report_file.write("                </vuln_attempt>\n")
        end
        report_file.write("            </vuln_attempts>\n")

        report_file.write("      </vuln>\n")
      end
      report_file.write("    </vulns>\n")

      # Credential sub-elements
      report_file.write("    <creds>\n")
      @creds.each do |cred|
        next unless cred.service.host.id == host_id
        report_file.write("      <cred>\n")
        report_file.write("      #{create_xml_element("port",cred.service.port)}\n")
        report_file.write("      #{create_xml_element("sname",cred.service.name)}\n")
        cred.attributes.each_pair do |k,v|
          next if k.strip =~ /id$/
          el = create_xml_element(k,v)
          report_file.write("      #{el}\n")
        end
        report_file.write("      </cred>\n")
      end
      report_file.write("    </creds>\n")

      report_file.write("  </host>\n")
    end
    report_file.flush
  end

  # Extract event data from @events
  def extract_event_info(report_file)
    @events.each do |e|
      report_file.write("  <event>\n")
      e.attributes.each_pair do |k,v|
        el = create_xml_element(k,v)
        report_file.write("      #{el}\n")
      end
      report_file.write("  </event>\n")
      report_file.write("\n")
    end
    report_file.flush
  end

  # Extract service data from @services
  def extract_service_info(report_file)
    @services.each do |e|
      report_file.write("  <service>\n")
      e.attributes.each_pair do |k,v|
        el = create_xml_element(k,v)
        report_file.write("      #{el}\n")
      end
      report_file.write("  </service>\n")
      report_file.write("\n")
    end
    report_file.flush
  end

  # Extract credential data from @creds
  def extract_credential_info(report_file)
    @creds.each do |c|
      report_file.write("  <credential>\n")
      c.attributes.each_pair do |k,v|
        cr = create_xml_element(k,v)
        report_file.write("      #{cr}\n")
      end
      report_file.write("  </credential>\n")
      report_file.write("\n")
    end
    report_file.flush
  end

  # Extract service data from @services
  def extract_service_info(report_file)
    @services.each do |e|
      report_file.write("  <service>\n")
      e.attributes.each_pair do |k,v|
        el = create_xml_element(k,v)
        report_file.write("      #{el}\n")
      end
      report_file.write("  </service>\n")
      report_file.write("\n")
    end
    report_file.flush
  end

  # Extract web site data from @web_sites
  def extract_web_site_info(report_file)
    @web_sites.each do |e|
      report_file.write("  <web_site>\n")
      e.attributes.each_pair do |k,v|
        el = create_xml_element(k,v)
        report_file.write("      #{el}\n")
      end

      site = e
      el = create_xml_element("host", site.service.host.address)
      report_file.write("      #{el}\n")

      el = create_xml_element("port", site.service.port)
      report_file.write("      #{el}\n")

      el = create_xml_element("ssl", site.service.name == "https")
      report_file.write("      #{el}\n")

      report_file.write("  </web_site>\n")
    end
    report_file.flush
  end

  # Extract web pages, forms, and vulns
  def extract_web_info(report_file, tag, entries)
    entries.each do |e|
      report_file.write("  <#{tag}>\n")
      e.attributes.each_pair do |k,v|
        el = create_xml_element(k,v)
        report_file.write("      #{el}\n")
      end

      site = e.web_site
      el = create_xml_element("vhost", site.vhost)
      report_file.write("      #{el}\n")

      el = create_xml_element("host", site.service.host.address)
      report_file.write("      #{el}\n")

      el = create_xml_element("port", site.service.port)
      report_file.write("      #{el}\n")

      el = create_xml_element("ssl", site.service.name == "https")
      report_file.write("      #{el}\n")

      report_file.write("  </#{tag}>\n")
    end
    report_file.flush
  end

  # Extract web pages
  def extract_web_page_info(report_file)
    extract_web_info(report_file, "web_page", @web_pages)
  end

  # Extract web forms
  def extract_web_form_info(report_file)
    extract_web_info(report_file, "web_form", @web_forms)
  end

  # Extract web vulns
  def extract_web_vuln_info(report_file)
    extract_web_info(report_file, "web_vuln", @web_vulns)
  end

end
end
end

