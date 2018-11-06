FactoryBot.define do
  factory :mdm_host, :class => Mdm::Host do
    #
    # Associations
    #
    association :workspace, :factory => :mdm_workspace

    #
    # Attributes
    #
    address { generate :mdm_ipv4_address }
    name { generate :mdm_host_name }
    mac { generate :mdm_host_mac }

    factory :full_mdm_host do
      arch { generate :mdm_host_arch }
      comm { generate :mdm_host_comm }
      comments { generate :mdm_host_comments }
      info { generate :mdm_host_info }
      os_flavor { generate :mdm_host_os_flavor }
      os_lang { generate :mdm_host_os_lang }
      os_name { generate :mdm_host_os_name }
      os_sp { generate :mdm_host_os_sp }
      purpose { generate :mdm_host_purpose }
      scope { generate :mdm_host_scope }
      state { generate :mdm_host_state }
      virtual_host { generate :mdm_host_virtual_host }
    end
  end

  sequence :mdm_host_name do |n|
    "mdm_host_#{n}"
  end

  sequence :mdm_host_arch, Mdm::Host::ARCHITECTURES.cycle

  sequence :mdm_host_comm do |n|
    "Mdm::Host#comm #{n}"
  end

  sequence :mdm_host_comments do |n|
    "Mdm::Host#comments #{n}"
  end

  sequence :mdm_host_info do |n|
    "Mdm::Host#info #{n}"
  end

  sequence :mdm_host_mac do |n|
    without_separators = "%012X" % n
    octet_strings = without_separators.scan(/.{2}/)
    formatted = octet_strings.join(':')

    formatted
  end

  sequence :mdm_host_os_flavor do |n|
    "Mdm::Host#os_flavor #{n}"
  end

  sequence :mdm_host_os_lang do |n|
    "Mdm::Host#os_lang #{n}"
  end

  sequence :mdm_host_os_name do |n|
    "Mdm::Host#os_name #{n}"
  end

  sequence :mdm_host_os_sp do |n|
    "Mdm::Host#os_sp #{n}"
  end

  sequence :mdm_host_purpose do |n|
    "Mdm::Host#purpose #{n}"
  end

  sequence :mdm_host_scope do |n|
    n.to_s
  end

  sequence :mdm_host_state, Mdm::Host::STATES.cycle

  virtual_hosts = ['VMWare', 'QEMU', 'XEN']
  sequence :mdm_host_virtual_host, virtual_hosts.cycle
end
