#
# = nessus-xmlrpc.rb: communicate with Nessus(4.2+) over XML RPC interface
#
# Author:: Vlatko Kosturjak
#
# (C) Vlatko Kosturjak, Kost. Distributed under GPL and BSD license (dual).
#
# == What is this library?
#
# This library is used for communication with Nessus over XML RPC interface.
# You can start, stop, pause and resume scan. Watch progress and status of scan,
# download report, etc.
#
# == Requirements
#
# Required libraries are standard Ruby libraries: uri, net/https and rexml/document.
#
# == Usage:
#
#  require 'nessus-xmlrpc'
#  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
#  if n.logged_in
# 	id,name = n.policy_get_first
# 	puts "using policy ID: " + id + " with name: " + name
# 	uid=n.scan_new(id,"textxmlrpc","127.0.0.1")
#	puts "status: " + n.scan_status(uid)
# 	while not n.scan_finished(uid)
# 		sleep 10
# 	end
#	content=n.report_file_download(uid)
# 	File.open('report.xml', 'w') {|f| f.write(content) }
#  end

require 'uri'
require 'net/https'
require 'rexml/document'

# NessusXMLRPC module
#
# Usage:
#
#  require 'nessus-xmlrpc'
#  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
#  if n.logged_in
# 	id,name = n.policy_get_first
# 	uid=n.scan_new(id,"textxmlrpc","127.0.0.1")
#	puts "status: " + n.scan_status(uid)
#  end
#
# Check NessusXMLRPCrexml for description of methods implemented
# (for both NessusXMLRPCnokogiri and NessusXMLRPCrexml).

module NessusXMLRPC

  # Class which uses standard REXML to parse nessus XML RPC replies.
  class NessusXMLRPC
    # initialize object: try to connect to Nessus Scanner using URL, user and password
    #
    # Usage:
    #
    #  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
    def initialize(url,user,password)
      if url == ''
        @nurl="https://localhost:8834/"
      else
        if url =~ /\/$/
          @nurl=url
        else
          @nurl=url + "/"
        end
      end
      @token=''
      #login(user,password)
    end

    # checks if we're logged in correctly
    #
    # returns: true if logged in, false if not
    #
    # Usage:
    #
    #  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
    #  if n.logged_in
    #	puts "Logged in"
    #  else
    #	puts "Error"
    #  end

    def logged_in
      if @token == ''
        return false
      else
        return true
      end
    end

    # send standard Nessus XML request and check
    #
    # returns: rexml/document root
    def nessus_request(uri, post_data)
      body=nessus_http_request(uri, post_data)
      # puts response.body
      docxml = REXML::Document.new(body)
      begin
        status = docxml.root.elements['status'].text
      rescue
        puts("Error connecting/logging to the server!")
        return
      end
      if status == "OK"
        return docxml
      else
        return ''
      end
    end

    # send standard Nessus HTTP request and check
    #
    # returns: body of response
    def nessus_http_request(uri, post_data)
      url = URI.parse(@nurl + uri)
      request = Net::HTTP::Post.new( url.path )
      request.set_form_data( post_data )
      if not defined? @https
        @https = Net::HTTP.new( url.host, url.port )
        @https.use_ssl = true
        @https.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end
      # puts request
      begin
        response = @https.request( request )
      rescue
        puts("error connecting to server: #{@nurl} with URI: #{uri}")
        exit
      end
      # puts response.body
      return response.body
    end

    # login with user & password and sets object-wide @token, @name and @admin
    def login(user, password)
      post = { "login" => user, "password" => password }
      docxml=nessus_request('login', post)
      if docxml == ''
        @token=''
      else
        @token = docxml.root.elements['contents'].elements['token'].text
        @name = docxml.root.elements['contents'].elements['user'].elements['name'].text
        @admin = docxml.root.elements['contents'].elements['user'].elements['admin'].text
        # puts "Got token:" + @token
        return @token
      end

    end

    #checks to see if the user is an admin
    def is_admin
      if @admin == "TRUE"
        return true
      end
      return false
    end

    # initiate new scan with policy id, descriptive name and list of targets
    #
    # returns: uuid of scan
    #
    # Usage:
    #
    #  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
    #  if n.logged_in
    # 	id,name = n.policy_get_first
    # 	puts "using policy ID: " + id + " with name: " + name
    # 	uid=n.scan_new(id,"textxmlrpc","127.0.0.1")
    #  end
    def scan_new(policy_id,scan_name,target)
      post= { "token" => @token, "policy_id" => policy_id, "scan_name" => scan_name, "target" => target }
      docxml=nessus_request('scan/new', post)
      if docxml == ''
        return ''
      else
        uuid=docxml.root.elements['contents'].elements['scan'].elements['uuid'].text
        return uuid
      end
    end

    # get uids of scans
    #
    # returns: array of uids of active scans
    def scan_list_uids
      post= { "token" => @token }
      docxml = nil
      docxml=nessus_request('scan/list', post)
      if docxml.nil?
        return
      end
      uuids=Array.new
      docxml.root.elements['contents'].elements['scans'].elements['scanList'].each_element('//scan') {|scan| uuids.push(scan.elements['uuid'].text) }
      return uuids
    end

    # get hash of active scan data
    #
    # returns: array of hash of active scans
    def scan_list_hash
      post= { "token" => @token }
      docxml = nil
      docxml=nessus_request('scan/list', post)
      if docxml.nil?
        return
      end
      scans=Array.new
      docxml.root.elements['contents'].elements['scans'].elements['scanList'].each_element('//scan') {|scan|
        entry=Hash.new
        entry['id']=scan.elements['uuid'].text if scan.elements['uuid']
        entry['name']=scan.elements['readableName'].text if scan.elements['readableName']
        entry['owner']=scan.elements['owner'].text if scan.elements['owner']
        entry['start']=scan.elements['start_time'].text if scan.elements['start_time']
        entry['status']=scan.elements['status'].text if scan.elements['status']
        entry['current']=scan.elements['completion_current'].text if scan.elements['completion_current']
        entry['total']=scan.elements['completion_total'].text if scan.elements['completion_total']
        scans.push(entry)
      }
      return scans
    end

    def template_list_hash
      post= { "token" => @token }
      docxml = nessus_request('scan/list', post)
      templates = Array.new
      docxml.elements.each('/reply/contents/templates/template') { |template|
        entry=Hash.new
        entry['name']=template.elements['name'].text if template.elements['name']
        entry['pid']=template.elements['policy_id'].text if template.elements['policy_id']
        entry['rname']=template.elements['readableName'].text if template.elements['readableName']
        entry['owner']=template.elements['owner'].text if template.elements['owner']
        entry['target']=template.elements['target'].text if template.elements['target']
        templates.push(entry)
      }
      return templates
    end

    # get hash of policies
    #
    # returns: array of hash of policies
    def policy_list_hash
      post= { "token" => @token }
      docxml = nil
      docxml=nessus_request('scan/list', post)
      if docxml.nil?
        return
      end
      policies=Array.new
      docxml.elements.each('/reply/contents/policies/policies/policy') { |policy|
        entry=Hash.new
        entry['id']=policy.elements['policyID'].text
        entry['name']=policy.elements['policyName'].text
        entry['comment']=policy.elements['policyComments'].text
        policies.push(entry)
      }
      return policies
    end

    # get hash of reportss
    #
    # returns: array of hash of templates
    def report_list_hash
      post= { "token" => @token }
      docxml = nil
      docxml=nessus_request('report/list', post)
      if docxml.nil?
        return
      end
      #puts docxml
      reports=Array.new
      docxml.root.elements['contents'].elements['reports'].each_element('//report') {|report|
        entry=Hash.new
        entry['id']=report.elements['name'].text if report.elements['name']
        entry['name']=report.elements['readableName'].text if report.elements['readableName']
        entry['status']=report.elements['status'].text if report.elements['status']
        entry['timestamp']=report.elements['timestamp'].text if report.elements['timestamp']
        reports.push(entry)
      }
      return reports
    end

    # get policy by textname and return policyID
    #
    # returns: policyID
    def policy_get_id(textname)
      post= { "token" => @token }
      docxml = nil
      docxml=nessus_request('policy/list', post)
      if docxml.nil?
        return
      end
      docxml.root.elements['contents'].elements['policies'].each_element('//policy') {|policy|
        if policy.elements['policyName'].text == textname
          return policy.elements['policyID'].text
        end
      }
      return ''
    end

    # get first policy from server and returns: policyID, policyName
    #
    # returns: policyID, policyName
    def policy_get_first
      post= { "token" => @token }
      docxml = nil
      docxml=nessus_request('policy/list', post)
      if docxml.nil?
        return
      end
      docxml.root.elements['contents'].elements['policies'].each_element('//policy') {|policy|
        return policy.elements['policyID'].text, policy.elements['policyName'].text
      }
    end

    # get list of policy IDs
    #
    # returns: array of all policy uids
    def policy_list_uids
      post= { "token" => @token }
      docxml = nil
      docxml=nessus_request('policy/list', post)
      if docxml.nil?
        return
      end
      pids=Array.new
      docxml.root.elements['contents'].elements['policies'].each_element('//policy') { |policy|
        pids.push(policy.elements['policyID'].text) }
      return pids
    end

    # stop scan identified by scan_uuid
    def scan_stop(uuid)
      post= { "token" => @token, "scan_uuid" => uuid }
      docxml = nil
      docxml=nessus_request('scan/stop', post)
      if docxml.nil?
        return
      end
      return docxml
    end

    # stop all active scans
    #
    # Usage:
    #
    #  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
    #  if n.logged_in
    #	n.scan_stop_all
    #  end
    def scan_stop_all
      b=scan_list_uids
      b.each {|uuid|
        scan_stop(uuid)
      }
      return b
    end

    # pause scan identified by scan_uuid
    def scan_pause(uuid)
      post= { "token" => @token, "scan_uuid" => uuid }
      docxml = nil
      docxml=nessus_request('scan/pause', post)
      if docxml.nil?
        return
      end
      return docxml
    end

    # pause all active scans
    #
    # Usage:
    #
    #  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
    #  if n.logged_in
    #	n.scan_pause_all
    #  end
    def scan_pause_all
      b=scan_list_uids
      b.each {|uuid|
        scan_pause(uuid)
      }
      return b
    end

    # remove scan identified by uuid
    def scan_resume(uuid)
      post= { "token" => @token, "scan_uuid" => uuid }
      docxml = nil
      docxml=nessus_request('scan/resume', post)
      if docxml.nil?
        return
      end
      return docxml
    end
    # resume all active scans
    #
    # Usage:
    #
    #  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
    #  if n.logged_in
    #	n.scan_resume_all
    #  end
    def scan_resume_all
      b=scan_list_uids
      b.each {|uuid|
        scan_resume(uuid)
      }
      return b
    end

    # check status of scan identified by uuid
    def scan_status(uuid)
      post= { "token" => @token, "report" => uuid }
      docxml = nil
      docxml=nessus_request('report/list', post)
      if docxml.nil?
        return
      end
      docxml.root.elements['contents'].elements['reports'].each_element('//report') { |report|
        if report.elements['name'].text == uuid
          return (report.elements['status'].text)
        end
      }
      return ''
    end

    # check if scan is finished (completed to be exact) identified by uuid
    def scan_finished(uuid)
      status=scan_status(uuid)
      if status == "completed"
        return true
      else
        return false
      end
    end

    # get report by reportID and return XML file
    #
    # returns: XML file of report (nessus v2 format)
    def report_file_download(report)
      post= { "token" => @token, "report" => report }
      file = nil
      file=nessus_http_request('file/report/download', post)
      if file.nil?
        return
      end
      return file
    end

    # get report by reportID and return XML file (version 1)
    #
    # returns: XML file of report (nessus v1 format)
    def report_file1_download(report)
      post= { "token" => @token, "report" => report, "v1" => "true" }

      file=nessus_http_request('file/report/download', post)

      return file
    end

    #
    # Uncommon report format accessors
    # https://discussions.nessus.org/message/20053#20053
    #

    # get report by reportID and return CSV file
    #
    # returns CSV file of report
    def report_csv_download(report)
      post= { "token" => @token, "report" => report, "xslt" => 'csv.xsl' }

      # Get CSV report location and build post params
      filename=nessus_http_request('file/xslt', post).scan(/fileName=(.*csv)/).flatten.first
      post= {"token" => @token, 'fileName' => filename, 'step' => 2}

      # Allow for generation time
      Rex::ThreadSafe.sleep(0.5)

      # Get CSV report
      file=nessus_http_request('file/xslt/download',post)

      return file
    end

    # get report by reportID and return nbe file
    #
    # returns nbe file of report
    def report_nbe_download(report)
      post= { "token" => @token, "report" => report, "xslt" => 'nbe.xsl' }

      # Get nbe report location and build post params
      filename=nessus_http_request('file/xslt', post).scan(/fileName=(.*nbe)/).flatten.first
      post= {"token" => @token, 'fileName' => filename, 'step' => 2}

      # Allow for generation time
      Rex::ThreadSafe.sleep(0.5)

      # Get nbe report
      file=nessus_http_request('file/xslt/download',post)

      return file
    end

    # get report chapters by reportID
    #
    # returns array of chapter names
    def report_get_chapters(report)
      post = {'token' => @token, 'report' => report}
      chapters = nessus_http_request('chapter/list',post)
      return Nokogiri::XML.parse(chapters).xpath('//chapter').children.map(&:text)
      return chapters
    end

    # get report by reportID, chapters by name, and return PDF file
    #
    # returns PDF file of report
    def report_pdf_download(report,chapters=nil)
      chapters ||= report_get_chapters(report)
      chapters = [chapters] if chapters.is_a?(String)
      post= { "token" => @token, "report" => report, 'format' => 'pdf', 'chapters' => chapters.join(';') }
      filename=nessus_http_request('chapter', post).scan(/fileName=(.*pdf)/).flatten.first
      post= {"token" => @token, 'fileName' => filename, 'step' => 2}

      # Allow for generation time
      Rex::ThreadSafe.sleep(0.5)

      # Get nbe report
      file=nessus_http_request('file/xslt/download',post)

      return file
    end

    # get report by reportID, chapters by name, and return HTML file
    #
    # returns HTML file of report
    def report_html_download(report,chapters=nil)
      chapters ||= report_get_chapters(report)
      chapters = [chapters] if chapters.is_a?(String)
      post= { "token" => @token, "report" => report, 'format' => 'html', 'chapters' => chapters.join(';') }
      filename=nessus_http_request('chapter', post).scan(/fileName=(.*html)/).flatten.first
      post= {"token" => @token, 'fileName' => filename, 'step' => 2}

      # Allow for generation time
      Rex::ThreadSafe.sleep(0.5)

      # Get nbe report
      file=nessus_http_request('file/xslt/download',post)

      return file
    end

    # delete report by report ID
    def report_delete(id)
      post= { "token" => @token, "report" => id }
      docxml = nil
      docxml=nessus_request('report/delete', post)
      if docxml.nil?
        return
      end
      return docxml
    end

    # get list of names of policies
    #
    # returns: array of names
    def policy_list_names
      post= { "token" => @token }
      docxml = nil
      docxml=nessus_request('policy/list', post)
      if docxml.nil?
        return
      end
      list = Array.new
      docxml.root.elements['contents'].elements['policies'].each_element('//policy') {|policy|
        list.push policy.elements['policyName'].text
      }
      return list
    end

    # get data for each host for a particular report
    #
    #
    # returns: array of hashes:
    #		hostname
    #		severity
    #		severityCount0
    #		severityCount1
    #		severityCount2
    #		severityCount3
    #		scanProgressCurrent
    #		scanprogressTotal
    def report_hosts(report_id)
      post= { "token" => @token, "report" => report_id }
      docxml = nil
      docxml=nessus_request('report/hosts', post)
      if docxml.nil?
        return
      end
      hosts=Array.new
      docxml.elements.each('/reply/contents/hostList/host') do |host|
        entry=Hash.new
        entry['hostname'] = host.elements['hostname'].text if host.elements['hostname']
        entry['severity'] = host.elements['severity'].text if host.elements['severity']
        sevs=Array.new
        host.elements.each('severityCount/item') do |item|
          sevs.push item.elements['count'].text if item.elements['count']
        end
        entry['sev0'] = sevs[0] if sevs[0]
        entry['sev1'] = sevs[1] if sevs[1]
        entry['sev2'] = sevs[2] if sevs[2]
        entry['sev3'] = sevs[3] if sevs[3]
        entry['current'] = host.elements['scanProgressCurrent'].text if host.elements['scanProgressCurrent']
        entry['total'] = host.elements['scanProgressTotal'].text if host.elements['scanProgressTotal']
        hosts.push(entry)
      end
      return hosts
    end

    def report_host_ports(report_id,host)
      post= { "token" => @token, "report" => report_id, "hostname" => host }
      docxml = nil
      docxml=nessus_request('report/ports', post)
      if docxml.nil?
        return
      end
      ports=Array.new
      docxml.elements.each('/reply/contents/portList/port') do |port|
        entry=Hash.new
        entry['portnum'] = port.elements['portNum'].text if port.elements['portNum']
        entry['protocol'] = port.elements['protocol'].text if port.elements['protocol']
        entry['severity'] = port.elements['severity'].text if port.elements['severity']
        entry['svcname'] = port.elements['svcName'].text if port.elements['svcName']
        sevs=Array.new
        port.elements.each('severityCount/item') do |item|
          sevs.push item.elements['count'].text if item.elements['count']
        end
        entry['sev0'] = sevs[0] if sevs[0]
        entry['sev1'] = sevs[1] if sevs[1]
        entry['sev2'] = sevs[2] if sevs[2]
        entry['sev3'] = sevs[3] if sevs[3]
        ports.push(entry)
      end
      return ports
    end

    def report_host_port_details(report_id,host,port,protocol)
      post= { "token" => @token, "report" => report_id, "hostname" => host, "port" => port, "protocol" => protocol }
      docxml = nil
      docxml=nessus_request('report/details', post)
      if docxml.nil?
        return
      end
      reportitems=Array.new
      docxml.elements.each('/reply/contents/portDetails/ReportItem') do |rpt|
        entry=Hash.new
        cve = Array.new
        bid = Array.new
        entry['port'] = rpt.elements['port'].text if rpt.elements['port']
        entry['severity'] = rpt.elements['severity'].text if rpt.elements['severity']
        entry['pluginID'] = rpt.elements['pluginID'].text if rpt.elements['pluginID']
        entry['pluginName'] = rpt.elements['pluginName'].text if rpt.elements['pluginName']
        entry['cvss_base_score'] = rpt.elements['data'].elements['cvss_base_score'].text if rpt.elements['data'].elements['cvss_base_score']
        entry['exploit_available'] = rpt.elements['data'].elements['exploit_available'].text if rpt.elements['data'].elements['exploit_available']
        if rpt.elements['data'].elements['cve']
          rpt.elements['data'].elements['cve'].each do |x|
            cve.push rpt.elements['data'].elements['cve'].text
          end
        end
        entry['cve'] = cve if cve
        entry['risk_factor'] = rpt.elements['data'].elements['risk_factor'].text if rpt.elements['data'].elements['risk_factor']
        entry['cvss_vector'] = rpt.elements['data'].elements['cvss_vector'].text if rpt.elements['data'].elements['cvss_vector']
        entry['solution'] = rpt.elements['data'].elements['solution'].text if rpt.elements['data'].elements['solution']
        entry['description'] = rpt.elements['data'].elements['description'].text if rpt.elements['data'].elements['description']
        entry['synopsis'] = rpt.elements['data'].elements['synopsis'].text if rpt.elements['data'].elements['synopsis']
        entry['see_also'] = rpt.elements['data'].elements['see_also'].text if rpt.elements['data'].elements['see_also']
        if rpt.elements['data'].elements['bid']
          rpt.elements['data'].elements['bid'].each do |y|
            bid.push rpt.elements['data'].elements['bid'].text
          end
        end
        entry['bid'] = bid if bid
        #entry['xref'] = rpt.elements['data'].elements['xref'].text # multiple of these
        entry['plugin_output'] = rpt.elements['data'].elements['plugin_output'].text if rpt.elements['data'].elements['plugin_output']
        reportitems.push(entry)
      end
      return reportitems
    end

    # get host details for particular host identified by report id
    #
    # returns: severity, current, total
    def report_get_host(report_id,hostname)
      post= { "token" => @token, "report" => report_id }
      docxml = nil
      docxml=nessus_request('report/hosts', post)
      if docxml.nil?
        return
      end
      docxml.elements.each('/reply/contents/hostList/host') do |host|
        if host.elements['hostname'].text == hostname
          severity = host.elements['severity'].text
          current = host.elements['scanProgressCurrent'].text
          total = host.elements['scanProgressTotal'].text
          return severity, current, total
        end
      end
    end

    # gets a list of each plugin family and the number of plugins for that family.
    def plugins_list
      post= { "token" => @token }
      docxml =  nil
      docxml=nessus_request('plugins/list', post)
      if docxml.nil?
        return
      end
      plugins=Array.new
      docxml.root.elements['contents'].elements['pluginFamilyList'].each_element('//family') { |plugin|
        entry=Hash.new
        entry['name']=plugin.elements['familyName'].text
        entry['num']=plugin.elements['numFamilyMembers'].text
        plugins.push(entry)
      }
      return plugins
    end

    #returns a list of users, if they are an admin and their last login time.
    def users_list
      post= { "token" => @token }
      docxml = nil
      docxml=nessus_request('users/list', post)
      if docxml.nil?
        return
      end
      users=Array.new
      docxml.root.elements['contents'].elements['users'].each_element('//user') { |user|
        entry=Hash.new
        entry['name']=user.elements['name'].text
        entry['admin']=user.elements['admin'].text
        entry['lastlogin']=user.elements['lastlogin'].text
        users.push(entry)
      }
      return users
    end

    # returns basic data about the feed type and versions.
    def feed
      post = { "token" => @token }
      docxml = nil
      docxml = nessus_request('feed', post)
      if docxml.nil?
        return
      end
      feed = docxml.root.elements['contents'].elements['feed'].text
      version = docxml.root.elements['contents'].elements['server_version'].text
      web_version = docxml.root.elements['contents'].elements['web_server_version'].text
      return feed, version, web_version
    end

    def user_add(user,pass)
      post= { "token" => @token, "login" => user, "password" => pass }
      docxml = nil
      docxml = nessus_request('users/add', post)
      if docxml.nil?
        return
      end
      return docxml
    end

    def user_del(user)
      post= { "token" => @token, "login" => user }
      docxml = nil
      docxml = nessus_request('users/delete', post)
      if docxml.nil?
        return
      end
      return docxml
    end

    def user_pass(user,pass)
      post= { "token" => @token, "login" => user, "password" => pass }
      docxml = nil
      docxml = nessus_request('users/chpasswd', post)
      if docxml.nil?
        return
      end
      return docxml
    end

    def plugin_family(fam)
      post = { "token" => @token, "family" => fam }
      docxml = nil
      docxml = nessus_request('plugins/list/family', post)
      if docxml.nil?
        return
      end
      family=Array.new
      docxml.elements.each('/reply/contents/pluginList/plugin') { |plugin|
        entry=Hash.new
        entry['filename'] = plugin.elements['pluginFileName'].text if plugin.elements['pluginFileName']
        entry['id'] = plugin.elements['pluginID'].text if plugin.elements['pluginID']
        entry['name'] = plugin.elements['pluginName'].text if plugin.elements['pluginName']
        family.push(entry)
      }
      return family
    end

    def policy_del(pid)
      post= { "token" => @token, "policy_id" => pid }
      docxml = nil
      docxml = nessus_request('policy/delete', post)
      if docxml.nil?
        return
      end
      return docxml
    end

    def report_del(rid)
      post= { "token" => @token, "report" => rid }
      docxml = nil
      docxml = nessus_request('report/delete', post)
      if docxml.nil?
        return
      end
      return docxml
    end

    def plugin_detail(pname)
      post = { "token" => @token, "fname" => pname }
      docxml = nil
      docxml = nessus_request('plugins/description', post)
      if docxml.nil?
        return
      end
      entry=Hash.new
      docxml.elements.each('reply/contents/pluginDescription') { |desc|
        entry['name'] = desc.elements['pluginName'].text
        entry['id'] = desc.elements['pluginID'].text
        entry['family'] = desc.elements['pluginFamily'].text
        desc.elements.each('pluginAttributes') { |attr|
          entry['exploit_ease'] = attr.elements['exploitability_ease'].text if attr.elements['exploitability_ease']
          entry['cvss_temporal_vector'] = attr.elements['cvss_temporal_vector'].text if attr.elements['cvss_temporal_vector']
          entry['solution'] = attr.elements['solution'].text if attr.elements['solution']
          entry['cvss_temporal_score'] = attr.elements['cvss_temporal_score'].text if attr.elements['cvss_temporal_score']
          entry['risk_factor'] = attr.elements['risk_factor'].text if attr.elements['risk_factor']
          entry['description'] = attr.elements['description'].text if attr.elements['description']
          entry['plugin_publication_date'] = attr.elements['plugin_publication_date'].text if attr.elements['plugin_publication_date']
          entry['cvss_vector'] = attr.elements['cvss_vector'].text if attr.elements['cvss_vector']
          entry['synopsis'] = attr.elements['synopsis'].text if attr.elements['synopsis']
          entry['exploit_available'] = attr.elements['exploit_available'].text if attr.elements['exploit_available']
          entry['plugin_modification_date'] = attr.elements['plugin_modification_date'].text if attr.elements['plugin_modification_date']
          entry['cvss_base_score'] = attr.elements['cvss_base_score'].text if attr.elements['cvss_base_score']
        }
      }
      return entry
    end

    def server_prefs
      post= { "token" => @token }
      docxml = nil
      docxml = nessus_request('preferences/list', post)
      if docxml.nil?
        return
      end
      prefs = Array.new
      docxml.elements.each('/reply/contents/ServerPreferences/preference') { |pref|
        entry=Hash.new
        entry['name'] = pref.elements['name'].text if pref.elements['name']
        entry['value']= pref.elements['value'].text if pref.elements['value']
        prefs.push(entry)
      }
      return prefs
    end

    def plugin_prefs
      post= { "token" => @token }
      docxml = nil
      docxml = nessus_request('plugins/preferences', post)
      if docxml.nil?
        return
      end
      prefs = Array.new
      docxml.elements.each('/reply/contents/PluginsPreferences/item') { |pref|
        entry=Hash.new
        entry['fullname'] = pref.elements['fullName'].text if pref.elements['fullName']
        entry['pluginname'] = pref.elements['pluginName'].text if pref.elements['pluginName']
        entry['prefname'] = pref.elements['preferenceName'].text if pref.elements['preferenceName']
        entry['preftype'] = pref.elements['preferenceType'].text if pref.elements['preferenceType']
        entry['prefvalues'] = pref.elements['preferenceValues'].text if pref.elements['preferenceValues']
        prefs.push(entry)
      }
      return prefs
    end
  end # end of NessusXMLRPC::Class

end # of Module
