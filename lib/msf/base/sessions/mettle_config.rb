# -*- coding: binary -*-

require 'msf/core/payload/transport_config'
require 'base64'

module Msf
module Sessions
module MettleConfig

  include Msf::Payload::TransportConfig

  def generate_config(opts={})
    transport = transport_config_reverse_tcp(opts)
    opts[:uuid] ||= generate_payload_uuid
    opts[:uuid] = Base64.encode64(opts[:uuid].to_raw).strip
    opts[:uri] ||= "#{transport[:scheme]}://#{transport[:lhost]}:#{transport[:lport]}"
    opts.slice(:uuid, :uri, :debug, :log_file)
  end

end
end
end
