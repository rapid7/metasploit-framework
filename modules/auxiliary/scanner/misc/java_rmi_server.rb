##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/java/serialization'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Java::Rmi::Client
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
          [ 'URL', 'http://www.securitytracker.com/id?1026215'],
          [ 'CVE', '2011-3556']
        ],
      'DisclosureDate' => 'Oct 15 2011'
    )

    register_options(
      [
        Opt::RPORT(1099)
      ])
  end

  def run_host(target_host)
    vprint_status("Sending RMI Header...")
    connect

    send_header
    ack = recv_protocol_ack
    if ack.nil?
      print_error("Failed to negotiate RMI protocol")
      disconnect
      return
    end

    # Determine if the instance allows remote class loading
    vprint_status("Sending RMI Call...")
    jar = Rex::Text.rand_text_alpha(rand(8)+1) + '.jar'
    jar_url = "file:RMIClassLoaderSecurityTest/" + jar

    dgc_interface_hash = calculate_interface_hash(
      [
        {
          name: 'clean',
          descriptor: '([Ljava/rmi/server/ObjID;JLjava/rmi/dgc/VMID;Z)V',
          exceptions: ['java.rmi.RemoteException']
        },
        {
          name: 'dirty',
          descriptor: '([Ljava/rmi/server/ObjID;JLjava/rmi/dgc/Lease;)Ljava/rmi/dgc/Lease;',
          exceptions: ['java.rmi.RemoteException']
        }
      ]
    )

    # JDK 1.1 stub protocol
    # Interface hash: 0xf6b6898d8bf28643 (sun.rmi.transport.DGCImpl_Stub)
    # Operation: 0 (public void clean(ObjID[] paramArrayOfObjID, long paramLong, VMID paramVMID, boolean paramBoolean))
    send_call(
      object_number: 2,
      uid_number: 0,
      uid_time: 0,
      uid_count: 0,
      operation: 0,
      hash: dgc_interface_hash,
      arguments: build_dgc_clean_args(jar_url)
    )
    return_value = recv_return

    if return_value.nil?
      print_good("Failed to send RMI Call, anyway JAVA RMI Endpoint detected")
      report_service(:host => rhost, :port => rport, :name => "java-rmi", :info => "")
      return
    end

    if return_value.is_exception? && loader_enabled?(return_value.value)
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

  def loader_enabled?(exception_stack)
    exception_stack.each do |exception|
      if exception.class == Rex::Java::Serialization::Model::NewObject &&
          exception.class_desc.description.class == Rex::Java::Serialization::Model::NewClassDesc &&
          exception.class_desc.description.class_name.contents == 'java.lang.ClassNotFoundException'&&
          [Rex::Java::Serialization::Model::NullReference, Rex::Java::Serialization::Model::Reference].include?(exception.class_data[0].class) &&
          !exception.class_data[1].contents.include?('RMI class loader disabled')
          return true
      end
    end

    false
  end

  # class: sun.rmi.trasnport.DGC
  # method: public void clean(ObjID[] paramArrayOfObjID, long paramLong, VMID paramVMID, boolean paramBoolean)
  def build_dgc_clean_args(jar_url)
    arguments = []

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

    # ObjID[] paramArrayOfObjID
    arguments << new_array

    # long paramLong
    arguments << Rex::Java::Serialization::Model::BlockData.new(nil, "\x00\x00\x00\x00\x00\x00\x00\x00")

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

    # VMID paramVMID
    arguments << new_object

    # boolean paramBoolean
    arguments << Rex::Java::Serialization::Model::BlockData.new(nil, "\x00")

    arguments
  end
end
