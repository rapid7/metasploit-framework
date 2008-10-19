#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..'))

require 'test/unit'
require 'rex/proto/smb.rb.ts'
require 'rex/proto/dcerpc.rb.ts'
require 'rex/proto/http.rb.ts'