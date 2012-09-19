=begin

= apache/erubis-run.rb

Copyright (C) 2007 Andrew R Jackson <arjackson at acm dot org>

Built from original by Shugo Maeda:
Copyright (C) 2001 Shugo Maeda <shugo@modruby.net>

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WAreqANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WAreqANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTEreqUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

== Overview

Apache::ErubisRun handles eRuby files with erubis

== Example of httpd.conf

 RubyRequire apache/erubis-run
 <Location /eruby>
 SetHandler ruby-object
 RubyHandler Apache::ErubisRun.instance
 </Location>

=end

require "singleton"
require "tempfile"
require "eruby"   # Still needed to bring in a couple useful helper methods
require "erubis"

module Erubis
 @@cgi = nil

 def self.cgi
   return @@cgi
 end

 def self.cgi=(cgi)
   @@cgi = cgi
 end
end

module Apache
 class ErubisRun
   include Singleton

   def handler(req)
     status = check_request(req)
     return status if(status != OK)

     filename = req.filename.dup
     filename.untaint
     erubis = compile(filename)
     prerun(req)
     begin
       run(erubis, filename)
     ensure
       postrun(req)
     end

     return OK
   end

   private

   def initialize
     @compiler = nil
   end

   def check_request(req)
     if(req.method_number == M_OPTIONS)
       req.allowed |= (1 << M_GET)
       req.allowed |= (1 << M_POST)
       return DECLINED
     end
     if(req.finfo.mode == 0)
       return NOT_FOUND
     end
     return OK
   end

   def compile(filename)
     @compiler = Erubis::Eruby.load_file(filename) # use caching version as much as possible
     return @compiler
   end

   def prerun(req)
     Erubis.cgi = nil
     req.setup_cgi_env
     Apache.chdir_file(req.filename)
   end

   def run(erubis, filename)
     binding = eval_string_wrap("binding")
     puts erubis.result(binding) # eval the code in the context of the same binding ERuby uses
   end

   def postrun(req)
     if(cgi = Erubis.cgi)
       # TODO: pull the content type header from the cgi object, if set there?
     elsif(req.sync_output or req.sync_header)
       # Do nothing: header has already been sent
     else
       unless(req.content_type)
         req.content_type = format("text/html;")
       end
       req.send_http_header
     end
   end
 end
end
