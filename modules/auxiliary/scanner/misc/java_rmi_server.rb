##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/java/serialization'

class Metasploit3 < Msf::Auxiliary

  include Msf::Java::Rmi::Client
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Java RMI Server Insecure Endpoint Code Execution Scanner',
      'Description' => 'Detect Java RMI endpoints',
      'Author'     => ['mihi', 'hdm'],
      'License'     => MSF_LICENSE,
      'References'     =>
        [
          # RMI protocol specification
          [ 'URL', 'http://download.oracle.com/javase/1.3/docs/guide/rmi/spec/rmi-protocol.html'],
          # Placeholder reference for matching
          [ 'MSF', 'java_rmi_server']
        ],
      'DisclosureDate' => 'Oct 15 2011'
    )

    register_options(
      [
        Opt::RPORT(1099)
      ], self.class)
  end

  def run_host(target_host)
    vprint_status("#{peer} - Sending RMI Header...")
    connect

    send_header
    ack = recv_protocol_ack
    if ack.nil?
      print_error("#{peer} - Filed to negotiate RMI protocol")
      disconnect
      return
    end

    # Determine if the instance allows remote class loading
    vprint_status("#{peer} - Sending RMI Call...")
    jar = Rex::Text.rand_text_alpha(rand(8)+1) + '.jar'
    jar_url = "file:RMIClassLoaderSecurityTest/" + jar

    send_call(call_data: build_gc_call_data(jar_url))
    return_data = recv_return

    if return_data.nil?
      print_error("#{peer} - Failed to send RMI Call, anyway JAVA RMI Endpoint detected")
      report_service(:host => rhost, :port => rport, :name => "java-rmi", :info => "")
      return
    end

    if loader_enabled?(return_data)
      print_good("#{rhost}:#{rport} Java RMI Endpoint Detected: Class Loader Enabled")
      svc = report_service(:host => rhost, :port => rport, :name => "java-rmi", :info => "Class Loader: Enabled")
      report_vuln(
        :host         => rhost,
        :service      => svc,
        :name         => self.name,
        :info         => "Module #{self.fullname} confirmed remote code execution via this RMI service",
        :refs         => self.references
      )
    else
      print_status("#{rhost}:#{rport} Java RMI Endpoint Detected: Class Loader Disabled")
      report_service(:host => rhost, :port => rport, :name => "java-rmi", :info => "Class Loader: Disabled")
    end
  end

  def loader_enabled?(stream)
    stream.contents.each do |content|
      if content.class == Rex::Java::Serialization::Model::NewObject &&
          content.class_desc.description.class == Rex::Java::Serialization::Model::NewClassDesc &&
          content.class_desc.description.class_name.contents == 'java.lang.ClassNotFoundException'&&
          content.class_data[0].class == Rex::Java::Serialization::Model::NullReference &&
          !content.class_data[1].contents.include?('RMI class loader disabled')
          return true
      end
    end

    false
  end

  def build_gc_call_data(jar_url)
    stream = Rex::Java::Serialization::Model::Stream.new

    block_data = Rex::Java::Serialization::Model::BlockData.new
    block_data.contents = "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf6\xb6\x89\x8d\x8b\xf2\x86\x43"
    block_data.length = block_data.contents.length

    stream.contents << block_data

    new_array_annotation = Rex::Java::Serialization::Model::Annotation.new
    new_array_annotation.contents = [
      Rex::Java::Serialization::Model::NullReference.new,
      Rex::Java::Serialization::Model::EndBlockData.new
    ]

    new_array_super = Rex::Java::Serialization::Model::ClassDesc.new
    new_array_super.description = Rex::Java::Serialization::Model::NullReference.new

    new_array_desc = Rex::Java::Serialization::Model::NewClassDesc.new
    new_array_desc.class_name =  Rex::Java::Serialization::Model::Utf.new(nil, '[Ljava.rmi.server.ObjID;')
    new_array_desc.serial_version = 0x871300b8d02c647e
    new_array_desc.flags = 2
    new_array_desc.fields = []
    new_array_desc.class_annotation = new_array_annotation
    new_array_desc.super_class = new_array_super

    array_desc = Rex::Java::Serialization::Model::ClassDesc.new
    array_desc.description = new_array_desc

    new_array = Rex::Java::Serialization::Model::NewArray.new
    new_array.type = 'java.rmi.server.ObjID;'
    new_array.values = []
    new_array.array_description = array_desc

    stream.contents << new_array
    stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, "\x00\x00\x00\x00\x00\x00\x00\x00")

    new_class_desc = Rex::Java::Serialization::Model::NewClassDesc.new
    new_class_desc.class_name = Rex::Java::Serialization::Model::Utf.new(nil, 'metasploit.RMILoader')
    new_class_desc.serial_version = 0xa16544ba26f9c2f4
    new_class_desc.flags = 2
    new_class_desc.fields = []
    new_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
    new_class_desc.class_annotation.contents = [
      Rex::Java::Serialization::Model::Utf.new(nil, jar_url),
      Rex::Java::Serialization::Model::EndBlockData.new
    ]
    new_class_desc.super_class = Rex::Java::Serialization::Model::ClassDesc.new
    new_class_desc.super_class.description = Rex::Java::Serialization::Model::NullReference.new

    new_object = Rex::Java::Serialization::Model::NewObject.new
    new_object.class_desc = Rex::Java::Serialization::Model::ClassDesc.new
    new_object.class_desc.description = new_class_desc
    new_object.class_data = []

    stream.contents << new_object

    stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, "\x00")

    stream
  end

end
