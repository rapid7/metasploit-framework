module RubySMB
  module SMB2
    module Dcerpc

      def net_share_enum_all(host)
        bind(endpoint: RubySMB::Dcerpc::Srvsvc)

        response = request(RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL, host: host)

        shares = RubySMB::Dcerpc::Srvsvc::NetShareEnumAll.parse_response(response.stub.to_binary_s)
        shares.map{|s|{name: s[0], type: s[1], comment: s[2]}}
      end

      def bind(options={})
        bind_req = RubySMB::Dcerpc::Bind.new(options)
        write(data: bind_req.to_binary_s)
        @size = 1024
        dcerpc_raw_response = read()
        begin
          dcerpc_response = RubySMB::Dcerpc::BindAck.read(dcerpc_raw_response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the DCERPC response"
        end
        unless dcerpc_response.pdu_header.ptype == RubySMB::Dcerpc::PTypes::BIND_ACK
          raise RubySMB::Dcerpc::Error::BindError, "Not a BindAck packet"
        end

        res_list = dcerpc_response.p_result_list
        if res_list.n_results == 0 ||
           res_list.p_results[0].result != RubySMB::Dcerpc::BindAck::ACCEPTANCE
          raise RubySMB::Dcerpc::Error::BindError,
            "Bind Failed (Result: #{res_list.p_results[0].result}, Reason: #{res_list.p_results[0].reason})"
        end
        dcerpc_response
      end

      def request(opnum, options={})
        dcerpc_request = RubySMB::Dcerpc::Request.new({ :opnum => opnum }, options)
        ioctl_response = ioctl_send_recv(dcerpc_request, options)
        begin
          dcerpc_response = RubySMB::Dcerpc::Response.read(ioctl_response.output_data)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the DCERPC response"
        end
        unless dcerpc_response.pdu_header.ptype == RubySMB::Dcerpc::PTypes::RESPONSE
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Not a Response packet"
        end
        dcerpc_response
      end

      def ioctl_send_recv(action, options={})
        request = set_header_fields(RubySMB::SMB2::Packet::IoctlRequest.new(options))
        request.ctl_code = 0x0011C017
        request.flags.is_fsctl = 0x00000001
        request.buffer = action.to_binary_s
        ioctl_raw_response = @tree.client.send_recv(request)
        ioctl_response = RubySMB::SMB2::Packet::IoctlResponse.read(ioctl_raw_response)
        unless ioctl_response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::IoctlRequest::COMMAND,
            received_proto: ioctl_response.smb2_header.protocol,
            received_cmd:   ioctl_response.smb2_header.command
          )
        end
        unless ioctl_response.status_code == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Error::UnexpectedStatusCode, ioctl_response.status_code.name
        end
        ioctl_response
      end

    end
  end
end

