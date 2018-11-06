# frozen_string_literal: true
require "benchmark"
require File.join(File.dirname(__FILE__), '..', 'lib', 'yard')

unless YARD::CodeObjects::Proxy.private_instance_methods.include?('to_obj')
  raise "This benchmark is dependent on YARD::CodeObjects::Proxy#to_obj"
end

def rungen
  YARD::Registry.clear
  YARD::CLI::Yardoc.run('--quiet', '--use-cache')
end

def redef(lock = false)
  eval <<-eof
    class YARD::CodeObjects::Proxy;
      def to_obj
        @obj #{lock ? '||' : ''}= YARD::Registry.resolve(@namespace, @name)
      end
    end
  eof
end

Benchmark.bmbm do |x|
  x.report("gen-w/o-locking")  { redef;       rungen }
  x.report("gen-with-locking") { redef(true); rungen }
end

=begin Results from 2008-06-07
Rehearsal ----------------------------------------------------
gen-w/o-locking    9.650000   0.450000  10.100000 ( 10.150556)
gen-with-locking   7.790000   0.400000   8.190000 (  8.373811)
------------------------------------------ total: 18.290000sec

                       user     system      total        real
gen-w/o-locking    9.820000   0.430000  10.250000 ( 10.293283)
gen-with-locking   7.820000   0.380000   8.200000 (  8.243326)
=end
