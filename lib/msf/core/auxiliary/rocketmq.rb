# -*- coding: binary -*-

module Msf
  ###
  #
  # This module provides methods for working with Arista equipment
  #
  ###
  module Auxiliary::Rocketmq
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
        vprint_status('Sending request')
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
      result
    end

    def get_rocketmq_version(id)
      # This function takes an ID (number) and looks through rocketmq's index of verison numbers to find the real version number
      # Errors will result in "UNKNOWN_VERSION_ID_<id>" and may be caused by needing to update the version table
      # from https://github.com/apache/rocketmq/blob/develop/common/src/4d82b307ef50f5cba5717d0ebafeb3cabf336873/java/org/apache/rocketmq/common/MQVersion.java
      version_list = JSON.parse(File.read(::File.join(Msf::Config.data_directory, 'rocketmq_versions_list.json'), mode: 'rb'))
      version_list.fetch(id, "UNKNOWN_VERSION_ID_#{id})")
    end
  end
end
