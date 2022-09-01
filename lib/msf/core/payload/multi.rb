# -*- coding: binary -*-

###
#
#
#
###
module Msf::Payload::Multi

  # TOOD: require the appropriate stuff!
  # TODO: figure out what to do here
  def apply_prepends(raw)
    ''
  end

  # TODO: figure out what to do here
  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Multi-Platform Meterpreter Payload',
      'Description'   => 'Detect and generate the appropriate payload based on platform/arch',
      'Author'        => ['OJ Reeves'],
      'Platform'      => ['multi'],
      'Arch'          => ARCH_ALL,
      'Stage'         => {'Payload' => ''},
      'PayloadCompat' => {'Convention' => 'sockedi sockrdi http https'},
      ))
  end

  # TODO: figure out what to do here
  def replace_var(raw, name, offset, pack)
    return true
  end

  # TODO: figure out what to do here
  def handle_intermediate_stage(conn, payload)
    return true
  end

end


