# -*- coding: binary -*-
require 'msf/core'

###
#
#
#
###
module Msf::Payload::Multi

  # TOOD: require the appropriate stuff!
  #require 'msf/core/payload/windows/dllinject'
  #require 'msf/core/payload/windows/exec'
  #require 'msf/core/payload/windows/loadlibrary'
  #require 'msf/core/payload/windows/meterpreter_loader'
  #require 'msf/core/payload/windows/x64/meterpreter_loader'
  #require 'msf/core/payload/windows/reflectivedllinject'
  #require 'msf/core/payload/windows/x64/reflectivedllinject'

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


