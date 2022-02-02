# -*- coding: binary -*-
# Copyright (c) 2010, patrickHVE@googlemail.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * The names of the author may not be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL patrickHVE@googlemail.com BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

require 'pp'
require 'enumerator'
require 'rex/post/meterpreter/extensions/stdapi/railgun/tlv'
require 'rex/post/meterpreter/extensions/stdapi/railgun/library_helper'
require 'rex/post/meterpreter/extensions/stdapi/railgun/buffer_item'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun

# A easier way to call multiple functions in a single request
class MultiCaller

  include LibraryHelper

  def initialize(client, parent, consts_mgr)
    @parent = parent
    @client = client

    # needed by LibraryHelper
    @consts_mgr = consts_mgr
  end

  def call(functions)
    request = Packet.create_request(COMMAND_ID_STDAPI_RAILGUN_API_MULTI)
    function_results = []
    call_layouts          = []
    functions.each do |f|
      lib_name, function, args = f
      library = @parent.get_library(lib_name)

      unless library
        raise "Library #{lib_name} has not been loaded"
      end

      unless function.instance_of? LibraryFunction
        function = library.functions[function]
        unless function
          raise "Library #{lib_name} function #{function} has not been defined"
        end
      end

      raise "#{function.params.length} arguments expected. #{args.length} arguments provided." unless args.length == function.params.length

      group, layouts = library.build_packet_and_layouts(
        Rex::Post::Meterpreter::GroupTlv.new(TLV_TYPE_RAILGUN_MULTI_GROUP),
        function,
        args,
        @client.native_arch
      )
      request.tlvs << group
      call_layouts << layouts
    end

    call_results = []
    res = @client.send_request(request)
    res.each(TLV_TYPE_RAILGUN_MULTI_GROUP) do |val|
      call_results << val
    end

    functions.each do |f|
      lib_name, function, args = f
      library = @parent.get_library(lib_name)
      function = library.functions[function] unless function.instance_of? LibraryFunction
      function_results << library.build_response(call_results.shift, function, call_layouts.shift, @client.native_arch)
    end

    function_results
  end
  # process_multi_function_call

end # MultiCall

end; end; end; end; end; end
