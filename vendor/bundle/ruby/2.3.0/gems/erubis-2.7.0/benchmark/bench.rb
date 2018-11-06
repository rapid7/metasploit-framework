#!/usr/bin/env ruby

###
### $Release: 2.7.0 $
### copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
###

require 'erb'
require 'erubis'
require 'erubis/tiny'
require 'erubis/engine/enhanced'
require 'yaml'
require 'cgi'
include ERB::Util

begin
  require 'eruby'
rescue LoadError
  ERuby = nil
end

def File.write(filename, content)
  File.open(filename, 'w') { |f| f.write(content) }
end


## change benchmark library to use $stderr instead of $stdout
require 'benchmark'
module Benchmark
  class Report
    def print(*args)
      $stderr.print(*args)
    end
  end
  module_function
  def print(*args)
    $stderr.print(*args)
  end
end


class BenchmarkApplication

  TARGETS = %w[eruby
               ERB               ERB(cached)
               Erubis::Eruby     Erubis::Eruby(cached)
               Erubis::FastEruby Erubis::FastEruby(cached)
               Erubis::TinyEruby
               Erubis::ArrayBufferEruby
               Erubis::PrintOutEruby
               Erubis::StdoutEruby
              ]

  def initialize(ntimes, context, targets=nil, params={})
    @ntimes      = ntimes
    @context     = context
    @targets     = targets && !targets.empty? ? targets : TARGETS.dup
    @testmode    = params[:testmode]    || 'execute'
    @erubyfile   = params[:erubyfile]   || 'erubybench.rhtml'
    @printout    = params[:printout]    || false
  end

  attr_accessor :ntimes, :targets
  attr_accessor :testmode, :erubyfile, :contextfile, :printout

  def context2code(context, varname='context')
    s = ''
    context.each { |k, | s << "#{k} = #{varname}[#{k.inspect}]; " }
    return s
  end

  def perform_benchmark
    width = 30
    $stderr.puts "*** ntimes=#{@ntimes}, testmode=#{@testmode}"
    Benchmark.bm(width) do |job|
      for target in @targets do
        method = "#{@testmode}_#{target.gsub(/::|-|\(/, '_').gsub(/\)/, '').downcase}"
        #$stderr.puts "*** debug: method=#{method.inspect}"
        next unless self.respond_to?(method)
        filename = "bench_#{(target =~ /^(\w+)/) && $1.downcase}.rhtml"
        title = target
        output = nil
        job.report(title) do
          output = self.__send__(method, filename, @context)
        end
        File.write("output.#{target.gsub(/[^\w]/,'')}", output) if @printout && output && !output.empty?
      end
    end
  end

  ##

  def execute_eruby(filename, context)
    return unless ERuby
    #eval context2code(context)
    list = context['list']
    @ntimes.times do
      ERuby.import(filename)
    end
    return nil
  end

  def execute_erb(filename, context)
    #eval context2code(context)
    list = context['list']
    output = nil
    @ntimes.times do
      eruby = ERB.new(File.read(filename))
      output = eruby.result(binding())
      print output
    end
    return output
  end

  def execute_erb_cached(filename, context)
    #eval context2code(context)
    list = context['list']
    output = nil
    cachefile = filename + '.cache'
    File.unlink(cachefile) if test(?f, cachefile)
    @ntimes.times do
      if !test(?f, cachefile) || File.mtime(filename) > File.mtime(cachefile)
        eruby = ERB.new(File.read(filename))
        File.write(cachefile, eruby.src)
      else
        eruby = ERB.new('')
        #eruby.src = File.read(cachefile)
        eruby.instance_variable_set("@src", File.read(cachefile))
      end
      output = eruby.result(binding())
      print output
    end
    return output
  end

  ## no cached
  for klass in %w[Eruby FastEruby TinyEruby ArrayBufferEruby PrintOutEruby StdoutEruby] do
    s = <<-END
    def execute_erubis_#{klass.downcase}(filename, context)
      #eval context2code(context)
      list = context['list']
      output = nil
      @ntimes.times do
        eruby = Erubis::#{klass}.new(File.read(filename))
        output = eruby.result(binding())
        print output
      end
      return output
    end
    END
    eval s
  end

  ## cached
  for klass in %w[Eruby FastEruby] do
    s = <<-END
    def execute_erubis_#{klass.downcase}_cached(filename, context)
      #eval context2code(context)
      list = context['list']
      cachefile = filename + '.cache'
      File.unlink(cachefile) if test(?f, cachefile)
      output = nil
      @ntimes.times do
        eruby = Erubis::#{klass}.load_file(filename)
        output = eruby.result(binding())
        print output
      end
      savefile = cachefile.sub(/\\.cache$/, '.#{klass.downcase}.cache')
      File.rename(cachefile, savefile)
      return output
    end
    END
    eval s
  end

  ##

  def convert_eruby(filename, context)
    return unless ERuby
    #eval context2code(context)
    list = context['list']
    output = nil
    @ntimes.times do
      output = ERuby::Compiler.new.compile_string(File.read(filename))
    end
    return output
  end

  def convert_erb(filename, context)
    #eval context2code(context)
    list = context['list']
    output = nil
    @ntimes.times do
      eruby = ERB.new(File.read(filename))
      output = eruby.src
    end
    return output
  end

  for klass in %w[Eruby FastEruby TinyEruby]
    s = <<-END
      def convert_erubis_#{klass.downcase}(filename, context)
        #eval context2code(context)
        list = context['list']
        output = nil
        @ntimes.times do
          eruby = Erubis::#{klass}.new(File.read(filename))
          output = eruby.src
        end
        return output
      end
    END
    eval s
  end

end


require 'optparse'

class MainApplication

  def parse_argv(argv=ARGV)
    optparser = OptionParser.new
    options = {}
    ['-h', '-n N', '-t erubyfile', '-f contextfile', '-A', '-e',
      '-x exclude', '-m testmode', '-X', '-p', '-D'].each do |opt|
      optparser.on(opt) { |val| options[opt[1].chr] = val }
    end
    begin
      targets = optparser.parse!(argv)
    rescue => ex
      $stderr.puts "#{@script}: #{ex.to_s}"
      exit(1)
    end
    return options, targets
  end

  def execute
    @script = File.basename($0)
    ntimes = 1000
    targets = BenchmarkApplication::TARGETS.dup
    testmode = 'execute'
    contextfile = 'bench_context.yaml'
    #
    options, args = parse_argv(ARGV)
    ntimes      = options['n'].to_i if options['n']
    targets     = args if args && !args.empty?
    targets     = targets - options['x'].split(/,/) if options['x']
    testmode    = options['m'] if options['m']
    contextfile = options['f'] if options['f']
    erubyfile   = options['t'] if options['t']
    #
    if options['h']
      $stderr.puts "Usage: ruby #{@script} [..options..] [..targets..]"
      $stderr.puts "  -h           :  help"
      $stderr.puts "  -n N         :  loop N times"
      $stderr.puts "  -f datafile  :  context data filename (*.yaml)"
      $stderr.puts "  -x exclude   :  exclude target name"
      $stdout.puts "  -m testmode  :  'execute' or 'convert' (default 'execute')"
      $stderr.puts "  -p           :  print output to file (filename: 'output.TARGETNAME')"
      return
    end
    #
    #if ! options['t']
    for item in %w[eruby erb erubis]
      fname = "bench_#{item}.rhtml"
      header = File.read("templates/_header.html")
      #body   = File.read("templates/#{erubyfile}")
      body   = File.read("templates/#{fname}")
      footer = File.read("templates/_footer.html")
      content = header + body + footer
      File.write(fname, content)
    end
    #
    if options['e']   # escape
      tuples = [
        [ 'bench_eruby.rhtml',  '<%= CGI.escapeHTML((\1).to_s) %>' ],
        [ 'bench_erb.rhtml',    '<%=h \1 %>' ],
        [ 'bench_erubis.rhtml', '<%== \1 %>' ],
      ]
      for fname, replace in tuples
        content = File.read(fname).gsub(/<%= ?(.*?) ?%>/, replace)
        File.write(fname, content)
      end
      targets.delete('Erubis::TinyEruby')   ## because TinyEruby doesn't support '<%== =>'
    end
    #
    context = YAML.load_file(contextfile)
    #
    params = {
      :printout=>options['p'],
      :testmode=>testmode,
    }
    app = BenchmarkApplication.new(ntimes, context, targets, params)
    app.perform_benchmark()
  end

end


if __FILE__ == $0

  ## open /dev/null
  $stdout = File.open('/dev/null', 'w')
  at_exit do
    $stdout.close()
  end

  ## start benchmark
  MainApplication.new().execute()

end
