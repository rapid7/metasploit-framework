#
# The Nexpose API
#
=begin

Copyright (C) 2009-2014, Rapid7 LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

    * Neither the name of Rapid7 LLC nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=end

#
# WARNING! This code makes an SSL connection to the Nexpose server, but does NOT
#          verify the certificate at this time. This can be a security issue if
#          an attacker is able to man-in-the-middle the connection between the
#          Metasploit console and the Nexpose server. In the common case of
#          running Nexpose and Metasploit on the same host, this is a low risk.
#

#
# WARNING! This code is still rough and going through substantive changes. While
#          you can build tools using this library today, keep in mind that
#          method names and parameters may change in the future.
#

require 'date'
require 'time'
require 'rexml/document'
require 'net/https'
require 'net/http'
require 'uri'
require 'ipaddr'
require 'json'
require 'cgi'
require 'nexpose/rexlite/mime'
require 'nexpose/api'
require 'nexpose/json_serializer'
require 'nexpose/error'
require 'nexpose/util'
require 'nexpose/alert'
require 'nexpose/ajax'
require 'nexpose/api_request'
require 'nexpose/asset'
require 'nexpose/blackout'
require 'nexpose/common'
require 'nexpose/console'
require 'nexpose/credential_helper'
require 'nexpose/credential'
require 'nexpose/site_credentials'
require 'nexpose/shared_credential'
require 'nexpose/web_credentials'
require 'nexpose/data_table'
require 'nexpose/device'
require 'nexpose/engine'
require 'nexpose/external'
require 'nexpose/filter'
require 'nexpose/discovery'
require 'nexpose/discovery/filter'
require 'nexpose/global_blackout'
require 'nexpose/global_settings'
require 'nexpose/group'
require 'nexpose/dag'
require 'nexpose/manage'
require 'nexpose/multi_tenant_user'
require 'nexpose/password_policy'
require 'nexpose/pool'
require 'nexpose/report'
require 'nexpose/report_template'
require 'nexpose/role'
require 'nexpose/scan'
require 'nexpose/scan_template'
require 'nexpose/scheduled_backup'
require 'nexpose/scheduled_maintenance'
require 'nexpose/shared_secret'
require 'nexpose/silo'
require 'nexpose/silo_profile'
require 'nexpose/site'
require 'nexpose/tag'
require 'nexpose/tag/criteria'
require 'nexpose/ticket'
require 'nexpose/user'
require 'nexpose/vuln'
require 'nexpose/vuln_def'
require 'nexpose/vuln_exception'
require 'nexpose/connection'
require 'nexpose/maint'
require 'nexpose/version'
require 'nexpose/wait'

# Double the size of the default limit,
# to work around large vuln content.
REXML::Security.entity_expansion_text_limit = 20_000

module Nexpose

  # Echos the last XML API request and response for the specified object.  (Useful for debugging)
  def self.print_xml(object)
    puts 'request: ' + object.request_xml.to_s
    puts 'response: ' + object.response_xml.to_s
  end
end
