# -*- coding: binary -*-

module Msf
  ###
  #
  # This module provides methods for working with Apache RocketMQ
  #
  ###
  module Auxiliary::Rocketmq
    include Msf::Exploit::Remote::Tcp
    def initialize(info = {})
      super
      register_options([ Opt::RPORT(9876) ], Msf::Auxiliary::Rocketmq)
    end

    def send_version_request
      # sends a version request to the service, and returns the data as a list of hashes. nil on error
      # https://github.com/Malayke/CVE-2023-33246_RocketMQ_RCE_EXPLOIT/blob/e27693a854a8e3b2863dc366f36002107e3595de/check.py#L68
      data = '{"code":105,"extFields":{"Signature":"/u5P/wZUbhjanu4LM/UzEdo2u2I=","topic":"TBW102","AccessKey":"rocketmq2"},"flag":0,"language":"JAVA","opaque":1,"serializeTypeCurrentRPC":"JSON","version":401}'
      data_length = "\x00\x00\x00" + [data.length].pack('C')
      header = "\x00\x00\x00" + [data.length + data_length.length].pack('C')

      begin
        connect
        sock.send(header + data_length + data, 0)
        res = sock.recv(1024)
      rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
        print_error("Unable to connect: #{e.class} #{e.message}\n#{e.backtrace * "\n"}")
        elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
      ensure
        disconnect
      end

      if res.nil?
        vprint_error('No response received')
        return nil
      end

      unless res.include?('{')
        vprint_error('Response contains unusable data')
        return nil
      end

      res
    end

    def get_rocketmq_version(id)
      # This function takes an ID (number) and looks through rocketmq's index of verison numbers to find the real version number
      # Errors will result in "UNKNOWN_VERSION_ID_<id>" and may be caused by needing to update the version table
      # from https://github.com/apache/rocketmq/blob/develop/common/src/4d82b307ef50f5cba5717d0ebafeb3cabf336873/java/org/apache/rocketmq/common/MQVersion.java
      version_list = JSON.parse(File.read(::File.join(Msf::Config.data_directory, 'rocketmq_versions_list.json'), mode: 'rb'))
      version_list.fetch(id, "UNKNOWN_VERSION_ID_#{id}").gsub('_', '.')
    end

    def parse_rocketmq_data(res)
      # remove a response header so we have json-ish data
      res = res[8..]

      # we have 2 json objects appended to eachother, so we now need to split that out and make it usable
      res = res.split('}{')

      jsonable = []
      # patch back in the { and }
      res.each do |r|
        r += '}' unless r.end_with?('}')
        r = '{' + r unless r.start_with?('{')
        jsonable.append(r)
      end

      result = []
      jsonable.each do |j|
        res = JSON.parse(j)
        result.append(res)
      rescue JSON::ParserError
        vprint_error("Unable to parse json data: #{j}")
        next
      end

      parsed_data = {}
      result.each do |j|
        parsed_data['version'] = get_rocketmq_version(j['version']) if j['version']
        parsed_data['brokerDatas'] = j['brokerDatas'] if j['brokerDatas']
      end

      if parsed_data == {} || parsed_data['version'].nil?
        vprint_error('Unable to find version or other data within response.')
        return
      end
      parsed_data
    end

    def get_broker_port(broker_datas, rhost, default_broker_port)
      # Example of brokerData:
      # [{"brokerAddrs"=>{"0"=>"172.16.199.135:10911"}, "brokerName"=>"DESKTOP-8ATHH6O", "cluster"=>"DefaultCluster"}]
      target_port = nil

      broker_datas['brokerDatas'].each do |broker_data|
        broker_data['brokerAddrs'].values.each do |broker_endpoint|
          next unless broker_endpoint.start_with?("#{rhost}:")
          return broker_endpoint.match(/\A#{rhost}:(\d+)\z/)[1].to_i
        end
      end


      if target_port.nil?
        print_status("autodetection failed, assuming default port of #{default_broker_port}")
        target_port = default_broker_port
      end
      target_port
    end
  end
end
