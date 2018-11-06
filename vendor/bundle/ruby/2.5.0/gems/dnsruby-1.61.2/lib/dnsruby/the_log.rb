# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++
require 'logger'
require 'singleton'
require 'thread'
module Dnsruby
  # This class exists for backwards compatibility.
  # 
  # It's Logger (which defaults to STDOUT, level FATAL) can be configured, or a new Logger can be supplied.
  # 
  #  Dnsruby::TheLog.level=Logger::DEBUG
  #  Dnsruby::TheLog.debug("Debug message")
  # 
  class TheLog
    #  Set a new Logger for use by Dnsruby
    def set_logger(logger)
      Dnsruby.log = logger
    end
    #  Change the Logger level.
    def level=(level)
      Dnsruby.log.level = level
    end
    def level
      return Dnsruby.log.level
    end

    def self.method_missing(symbol, *args) #:nodoc: all
        Dnsruby.log.send(symbol, *args)
    end
  end
end