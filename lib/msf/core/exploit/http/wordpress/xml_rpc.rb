# -*- coding: binary -*-

module Msf::Exploit::Remote::HTTP::Wordpress::XmlRpc

  # Determines if the XMLRPC interface is enabled by sending a demo.sayHello request
  #
  # @return [Boolean] true if the interface is enabled
  def wordpress_xmlrpc_enabled?
    xml = wordpress_generate_xml_rpc_body('demo.sayHello')

    res = send_request_cgi(
    'uri'       => wordpress_url_xmlrpc,
    'method'    => 'POST',
    'ctype'     => 'text/xml;charset=UTF-8',
    'data'      => xml
    )

    return true if res && res.body && res.body.to_s =~ /<string>Hello!<\/string>/
    return false
  end

  # Generates the xml post body for a XMLRPC call
  #
  # @param method_name [String] The XMLRPC method to call
  # @param params [String] The XMLRPC method params
  # @return [String] xml string
  def wordpress_generate_xml_rpc_body(method_name, *params)
    xml = "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>"
    xml << "<methodCall>"
    xml << "<methodName>#{method_name}</methodName>"
    xml << "<params>"
    params.each do |p|
      xml << "<param><value><string>#{p}</string></value></param>"
    end
    xml << "</params>"
    xml << "</methodCall>"
    return xml
  end

end
