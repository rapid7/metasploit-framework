shared_context 'metasploit_super_class_by_module_type' do
  let(:metasploit_super_class) do
    metasploit_super_class_by_module_type.fetch(module_type)
  end

  let(:metasploit_super_class_by_module_type) do
    {
        'auxiliary' => Msf::Auxiliary,
        'encoder' => Msf::Encoder,
        'exploit' => Msf::Exploit,
        'nop' => Msf::Nop,
        'payload' => Msf::Payload,
        'post' => Msf::Post
    }
  end
end