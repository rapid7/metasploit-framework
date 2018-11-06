FactoryBot.define do
  factory :mdm_listener, :aliases => [:listener], :class => Mdm::Listener do
    #
    # Associations
    #
    association :workspace, :factory => :mdm_workspace
    association :task, :factory => :mdm_task

    address { generate :mdm_ipv4_address }
    port { generate :mdm_tcp_port }
  end
end
