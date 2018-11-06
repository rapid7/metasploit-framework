# frozen_string_literal: true
require 'rubygems'
require 'erubis'
require 'erubis/tiny'
require 'erb'
require "benchmark"
require File.join(File.dirname(__FILE__), '..', 'lib', 'yard')

def rungen
  YARD::Registry.load_yardoc(File.join(File.dirname(__FILE__), '..', '.yardoc'))
  YARD::Registry.at("YARD::CodeObjects::Base").format(:format => :html)
end

Benchmark.bmbm do |x|
  x.report("erubis") do
    eval <<-eof
      module YARD; module Templates; module Template
        def erb_with(str, x) Erubis::Eruby.new(str) end
      end end end
    eof

    rungen
  end

  x.report("fast-erubis") do
    eval <<-eof
      module YARD; module Templates; module Template
        def erb_with(str, x) Erubis::FastEruby.new(str) end
      end end end
    eof

    rungen
  end

  x.report("tiny-erubis") do
    eval <<-eof
      module YARD; module Templates; module Template
        def erb_with(str, x) Erubis::TinyEruby.new(str) end
      end end end
    eof

    rungen
  end

  x.report("erb") do
    eval <<-eof
       module YARD; module Templates; module Template
        def erb_with(str, x) ERB.new(str) end
      end end end
    eof

    rungen
  end
end
