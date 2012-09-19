###
### $Release: 2.7.0 $
### copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
###

require 'yaml'

require 'test/unit/testcase'



def ruby18?  # :nodoc:
  RUBY_VERSION =~ /\A1.8/
end

def ruby19?  # :nodoc:
  RUBY_VERSION =~ /\A1.9/
end

def rubinius?  # :nodoc:
  defined?(RUBY_ENGINE) && RUBY_ENGINE == "rbx"
end



class Test::Unit::TestCase


  def self.load_yaml_datafile(filename, options={}, &block)  # :nodoc:
    # read datafile
    s = File.read(filename)
    if filename =~ /\.rb$/
      s =~ /^__END__$/   or raise "*** error: __END__ is not found in '#{filename}'."
      s = $'
    end
    # untabify
    s = _untabify(s) unless options[:tabify] == false
    # load yaml document
    testdata_list = []
    YAML.load_documents(s) do |ydoc|
      if ydoc.is_a?(Hash)
        testdata_list << ydoc
      elsif ydoc.is_a?(Array)
        ydoc.each do |hash|
          raise "testdata should be a mapping." unless hash.is_a?(Hash)
          testdata_list << hash
        end
      else
        raise "testdata should be a mapping."
      end
    end
    # data check
    identkey = options[:identkey] || 'name'
    table = {}
    testdata_list.each do |hash|
      ident = hash[identkey]
      ident          or  raise "*** key '#{identkey}' is required but not found."
      table[ident]   and raise "*** #{identkey} '#{ident}' is duplicated."
      table[ident] = hash
      yield(hash) if block
    end
    #
    return testdata_list
  end


  def self.define_testmethods(testdata_list, options={}, &block)
    identkey   = options[:identkey]   || 'name'
    testmethod = options[:testmethod] || '_test'
    testdata_list.each do |hash|
      yield(hash) if block
      ident = hash[identkey]
      s  =   "def test_#{ident}\n"
      hash.each do |key, val|
        s << "  @#{key} = #{val.inspect}\n"
      end
      s  <<  "  #{testmethod}\n"
      s  <<  "end\n"
      $stderr.puts "*** load_yaml_testdata(): eval_str=<<'END'\n#{s}END" if $DEBUG
      self.module_eval s
    end
  end


  def self.post_definition
    if ENV['TEST']
      target = "test_#{ENV['TEST']}"
      self.instance_methods.each do |method_name|
        m = method_name.to_s
        private m if m =~ /\Atest_/ && m != target
      end
    end
  end


  def self._untabify(str, width=8)
      return str if str.nil?
      list = str.split(/\t/, -1)   # if 2nd arg is negative then split() doesn't remove tailing empty strings
      last = list.pop
      sb = ''
      list.each do |s|
        column = (n = s.rindex(?\n)) ? s.length - n - 1 : s.length
        n = width - (column % width)
        sb << s << (' ' * n)
      end
      sb << last if last
      return sb
  end


end
