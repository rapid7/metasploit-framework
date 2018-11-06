##
## $Rev$
## $Release: 2.7.0 $
## $Date$
##

require  "#{File.dirname(__FILE__)}/test.rb"

require 'tempfile'
require 'fileutils'
require 'erubis/main'


$script = File.dirname(TESTDIR) + '/bin/erubis'
#if test(?f, 'bin/erubis')
#  $script = 'bin/erubis'
#elsif test(?f, '../bin/erubis')
#  $script = '../bin/erubis'
#end


class StringWriter < String
  def write(arg)
    self << arg
  end
  def flush(*args)
    # pass
  end
  def puts(arg)
    case arg
    when Array
      arg.each do |item|
        self << item << "\n"
      end
    else
      self << arg.to_s
      self << "\n" unless arg =~ /\n$/
    end
  end
end

class Erubis::Main
  public :usage
  public :show_properties
  public :show_enhancers
end


class MainTest < Test::Unit::TestCase

  INPUT = <<'END'
list:
<% list = ['<aaa>', 'b&b', '"ccc"']
   for item in list %>
  - <%= item %>
<% end %>
user: <%= defined?(user) ? user : "(none)" %>
END
  INPUT2 = INPUT.gsub(/\blist([^:])/, '@list\1').gsub(/\buser([^:])/, '@user\1')

#  SRC = <<'END'
#_buf = ''; _buf << "list:\n"
# list = ['<aaa>', 'b&b', '"ccc"']
#   for item in list
#_buf << "  - "; _buf << ( item ).to_s; _buf << "\n"
# end
#_buf << "user: "; _buf << ( defined?(user) ? user : "(none)" ).to_s; _buf << "\n"
#_buf
#END
  SRC = <<'END'
_buf = ''; _buf << 'list:
'; list = ['<aaa>', 'b&b', '"ccc"']
   for item in list 
 _buf << '  - '; _buf << ( item ).to_s; _buf << '
'; end 
 _buf << 'user: '; _buf << ( defined?(user) ? user : "(none)" ).to_s; _buf << '
';
_buf.to_s
END
#  SRC2 = SRC.gsub(/\blist /, '@list ').gsub(/\buser /, '@user ')

  OUTPUT = <<'END'
list:
  - <aaa>
  - b&b
  - "ccc"
user: (none)
END

  ESCAPED_OUTPUT = <<'END'
list:
  - &lt;aaa&gt;
  - b&amp;b
  - &quot;ccc&quot;
user: (none)
END


  PI_INPUT = <<'END'
<ul>
  <?rb @list = ['<aaa>', 'b&b', '"ccc"']
   for item in @list ?>
  <li>@{item}@ / @!{item}@
      <%= item %> / <%== item %></li>
  <?rb end ?>
<ul>
END

  PI_SRC = <<'END'
_buf = ''; _buf << '<ul>
';   @list = ['<aaa>', 'b&b', '"ccc"']
   for item in @list 
 _buf << '  <li>'; _buf << Erubis::XmlHelper.escape_xml(item); _buf << ' / '; _buf << (item).to_s; _buf << '
      '; _buf << ( item ).to_s; _buf << ' / '; _buf << Erubis::XmlHelper.escape_xml( item ); _buf << '</li>
';   end 
 _buf << '<ul>
';
_buf.to_s
END

  PI_ESCAPED_SRC = <<'END'
_buf = ''; _buf << '<ul>
';   @list = ['<aaa>', 'b&b', '"ccc"']
   for item in @list 
 _buf << '  <li>'; _buf << (item).to_s; _buf << ' / '; _buf << Erubis::XmlHelper.escape_xml(item); _buf << '
      '; _buf << Erubis::XmlHelper.escape_xml( item ); _buf << ' / '; _buf << ( item ).to_s; _buf << '</li>
';   end 
 _buf << '<ul>
';
_buf.to_s
END

  PI_OUTPUT = <<'END'
<ul>
  <li>&lt;aaa&gt; / <aaa>
      <aaa> / &lt;aaa&gt;</li>
  <li>b&amp;b / b&b
      b&b / b&amp;b</li>
  <li>&quot;ccc&quot; / "ccc"
      "ccc" / &quot;ccc&quot;</li>
<ul>
END

  PI_ESCAPED_OUTPUT = <<'END'
<ul>
  <li><aaa> / &lt;aaa&gt;
      &lt;aaa&gt; / <aaa></li>
  <li>b&b / b&amp;b
      b&amp;b / b&b</li>
  <li>"ccc" / &quot;ccc&quot;
      &quot;ccc&quot; / "ccc"</li>
<ul>
END

  def _test()
    if @filename.nil?
      method = (caller[0] =~ /in `(.*)'/) && $1    #'
      method =~ /block in (.*)/ and method = $1    # for Ruby 1.9
      @filename = "tmp.#{method}"
    end
    File.open(@filename, 'w') {|f| f.write(@input) } if @filename
    begin
      argv = @options.is_a?(Array) ? @options.dup : @options.split
      argv << @filename if @filename
      $stdout = output = StringWriter.new
      Erubis::Main.new.execute(argv)
    ensure
      $stdout = STDOUT
      File.unlink(@filename) if @filename && test(?f, @filename)
    end
    assert_text_equal(@expected, output)
  end

  def _error_test(errclass, errmsg)
    ex = assert_raise(errclass) { _test() }
    assert_equal(errmsg, ex.message)
  end


  def test_help      # -h
    @options = '-h'
    m = Erubis::Main.new
    @expected = m.usage() + "\n" + m.show_properties() + m.show_enhancers()
    @filename = false
    _test()
  end

  def test_version    # -v
    @options = '-v'
    @expected = (("$Release: 2.7.0 $" =~ /[.\d]+/) && $&) + "\n"
    @filename = false
    _test()
  end


  def test_basic1
    @input    = INPUT
    @expected = OUTPUT
    @options  = ''
    _test()
  end


  def test_source1    # -x
    @input    = INPUT
    @expected = SRC
    @options  = '-x'
    _test()
  end


  def _with_dummy_file
    bindir = File.join(File.dirname(File.dirname(__FILE__)), 'bin')
    env_path = ENV['PATH']
    env__    = ENV['_']
    begin
      ENV['PATH'] = bindir + File::PATH_SEPARATOR + ENV['PATH']
      ENV['_'] = 'erubis'
      Tempfile.open(self.name.gsub(/[^\w]/,'_')) do |f|
        f.write(INPUT)
        f.flush
        yield(f.path)
      end
    ensure
      ENV['PATH'] = env_path
      ENV['_']    = env__    if env__
    end
  end


  def test_syntax1    # -z (syntax ok)
    @input    = INPUT
    @expected = "Syntax OK\n"
    @options  = '-z'
    _test()
    #
    _with_dummy_file do |filepath|
      actual = `erubis #{@options} #{filepath}`
      assert_equal @expected, actual
    end
  end


  def test_syntax2    # -z (syntax error)
    inputs = []
    inputs << <<'END'
<ul>
<% for item in list %>
  <li><%= item[:name]] %></li>
<% end %>
</ul>
END
    inputs << <<'END'
<ul>
<% for item in list %>
  <li><%= item[:name] %></li>
<% edn %>
</ul>
END
    basename = 'tmp.test_syntax2_%d.rhtml'
    filenames = [ basename % 0, basename % 1 ]
    errmsgs = []
    if ruby19?
      errmsgs << <<'END'
3: syntax error, unexpected ']', expecting ')'
 _buf << '  <li>'; _buf << ( item[:name]] ).to_s; _buf << '</li>
                                         ^
-:4: syntax error, unexpected keyword_end, expecting ')'
'; end 
      ^
-:7: syntax error, unexpected $end, expecting ')'
END
      errmsgs << <<'END'
7: syntax error, unexpected $end, expecting keyword_end
END
    elsif rubinius?
      errmsgs << <<'END'
3: expecting ')'
 _buf << '  <li>'; _buf << ( item[:name]] ).to_s; _buf << '</li>
                                        ^
END
      errmsgs << <<'END'
7: missing 'end' for 'for' started on line 2
_buf.to_s
         ^
END
    else
      errmsgs << <<'END'
3: syntax error, unexpected ']', expecting ')'
 _buf << '  <li>'; _buf << ( item[:name]] ).to_s; _buf << '</li>
                                         ^
-:4: syntax error, unexpected kEND, expecting ')'
'; end 
      ^
-:7: syntax error, unexpected $end, expecting ')'
END
      errmsgs << <<'END'
7: syntax error, unexpected $end, expecting kEND
END
    end
    #
    max = inputs.length
    (0...max).each do |i|
      @input    = inputs[i]
      @expected = "tmp.test_syntax2:#{errmsgs[i]}"
      @options  = '-z'
      if rubinius?
        @expected.sub! /unexpected kEND/, 'unexpected keyword_end'
        @expected.sub! /expecting kEND/, 'expecting keyword_end'
      end
      _test()
    end
    #
    begin
      (0...max).each do |i|
        File.open(filenames[i], 'w') {|f| f.write(inputs[i]) }
      end
      @input = '<ok/>'
      @expected = ''
      @options = '-z'
      (0...max).each do |i|
        @expected << "#{filenames[i]}:#{errmsgs[i]}"
        @options << " #{filenames[i]}"
      end
      if rubinius?
        @expected.sub! /unexpected kEND/, 'unexpected keyword_end'
        @expected.sub! /expecting kEND/, 'expecting keyword_end'
      end
      _test()
    ensure
      (0...max).each do |i|
        File.unlink(filenames[i]) if test(?f, filenames[i])
      end
    end
  end


  def test_pattern1   # -p
    @input    = INPUT.gsub(/<%/, '<!--%').gsub(/%>/, '%-->')
    @expected = OUTPUT
    #@options  = "-p '<!--% %-->'"
    @options  = ["-p", "<!--% %-->"]
    _test()
  end


#  def test_class1     # -C
#    @input    = INPUT
#    @expected = OUTPUT.gsub(/<aaa>/, '&lt;aaa&gt;').gsub(/b&b/, 'b&amp;b').gsub(/"ccc"/, '&quot;ccc&quot;')
#    @options  = "-C XmlEruby"
#    _test()
#  end


  def test_notrim1    # --trim=false
    @input   = INPUT
    @expected = <<'END'
list:

  - <aaa>

  - b&b

  - "ccc"

user: (none)
END
    @options = "--trim=false"  # -T
    _test()
  end


  def test_notrim2    # --trim=false
    @input    = INPUT
#    @expected = <<'END'
#_buf = ''; _buf << "list:\n"
# list = ['<aaa>', 'b&b', '"ccc"']
#   for item in list ; _buf << "\n"
#_buf << "  - "; _buf << ( item ).to_s; _buf << "\n"
# end ; _buf << "\n"
#_buf << "user: "; _buf << ( defined?(user) ? user : "(none)" ).to_s; _buf << "\n"
#_buf
#END
    @expected = <<'END'
_buf = ''; _buf << 'list:
'; list = ['<aaa>', 'b&b', '"ccc"']
   for item in list ; _buf << '
'; _buf << '  - '; _buf << ( item ).to_s; _buf << '
'; end ; _buf << '
'; _buf << 'user: '; _buf << ( defined?(user) ? user : "(none)" ).to_s; _buf << '
';
_buf.to_s
END
    @options = "-x --trim=false"   # -xT
    _test()
  end


  #--
  #def test_context1
  #  @input    = INPUT
  #  @expected = OUTPUT.gsub(/\(none\)/, 'Hello')
  #  @options  = '--user=Hello'
  #  _test()
  #end
  #++


  def test_datafile1      # -f data.yaml
    datafile = "test.context1.yaml"
    @input    = INPUT2
    @expected = OUTPUT.gsub(/\(none\)/, 'Hello')
    @options  = "-f #{datafile}"
    #
    str = <<-END
    user:  Hello
    password:  world
    END
    File.open(datafile, 'w') {|f| f.write(str) }
    begin
      _test()
    ensure
      File.unlink(datafile) if test(?f, datafile)
    end
  end


  def test_datafile2      # -f data.rb
    datafile = "test.context1.rb"
    @input    = INPUT2
    @expected = OUTPUT.gsub(/\(none\)/, 'Hello')
    @options  = "-f #{datafile}"
    #
    str = <<-END
    @user = 'Hello'
    @password = 'world'
    END
    File.open(datafile, 'w') {|f| f.write(str) }
    begin
      _test()
    ensure
      File.unlink(datafile) if test(?f, datafile)
    end
  end


  def test_untabify1  # -t (obsolete)
    yamlfile = "test.context2.yaml"
    @input    = INPUT2
    @expected = OUTPUT.gsub(/\(none\)/, 'Hello')
    @options  = "-tf #{yamlfile}"
    #
    yaml = <<-END
    user:	Hello
    password:	world
    END
    File.open(yamlfile, 'w') {|f| f.write(yaml) }
    begin
      _test()
    ensure
      File.unlink(yamlfile) if test(?f, yamlfile)
    end
  end


  def test_untabify2  # -T
    yamlfile = "test.context2.yaml"
    @input    = INPUT2
    @expected = OUTPUT.gsub(/\(none\)/, 'Hello')
    @options  = "-Tf #{yamlfile}"
    #
    yaml = <<-END
    user: Hello
    items:
	- aaa
	- bbb
	- ccc
    END
    File.open(yamlfile, 'w') {|f| f.write(yaml) }
    assert_raise(ArgumentError) do
      _test()
    end
    File.open(yamlfile, 'w') {|f| f.write(yaml.gsub(/\t/, ' '*8)) }
    _test()
  ensure
      File.unlink(yamlfile) if test(?f, yamlfile)
  end


  def test_symbolify1 # -S
    yamlfile = "test.context3.yaml"
    @input    = <<END
<% for h in @list %>
<tr>
 <td><%= h[:name] %></td><td><%= h[:mail] %></td>
</tr>
<% end %>
END
    @expected = <<END
<tr>
 <td>foo</td><td>foo@mail.com</td>
</tr>
<tr>
 <td>bar</td><td>bar@mail.org</td>
</tr>
END
    @options  = "-f #{yamlfile} -S"
    #
    yaml = <<-END
list:
  - name:  foo
    mail:  foo@mail.com
  - name:  bar
    mail:  bar@mail.org
END
    File.open(yamlfile, 'w') { |f| f.write(yaml) }
    begin
      _test()
    ensure
      File.unlink(yamlfile) if test(?f, yamlfile)
    end
  end


  def test_result1   # -B
    yamlfile = "test.context4.yaml"
    #
    @input = <<'END'
user = <%= user %>
<% for item in list %>
 - <%= item %>
<% end %>
END
    @expected = <<'END'
user = World
 - aaa
 - bbb
 - ccc
END
    @options = "-f #{yamlfile} -B "
    #
    yaml = <<-END
user: World
list:
  - aaa
  - bbb
  - ccc
END
    File.open(yamlfile, 'w') {|f| f.write(yaml) }
    begin
      _test()
    ensure
      File.unlink(yamlfile) if test(?f, yamlfile)
    end
  end


  def test_context1   # -c
    @input = <<'END'
user = <%= @user %>
<% for item in @list %>
 - <%= item %>
<% end %>
END
    @expected = <<'END'
user = World
 - aaa
 - bbb
 - ccc
END
    #
    @options = ['-c', '{user: World, list: [aaa, bbb, ccc]}']
    _test()
    @options = ['-c', '@user="World"; @list=%w[aaa bbb ccc]']
    _test()
  end


  def test_include1   # -I
    dir = 'foo'
    lib = 'bar'
    Dir.mkdir dir unless test(?d, dir)
    filename = "#{dir}/#{lib}.rb"
    File.open(filename, 'w') do |f|
      f.write <<-'END'
        def escape(str)
          return "<#{str.upcase}>"
        end
      END
    end
    #
    @input    = "<% require '#{lib}' %>\n" + INPUT.gsub(/<%= item %>/, '<%= escape(item) %>')
    @expected = OUTPUT.gsub(/<aaa>/, '<<AAA>>').gsub(/b\&b/, '<B&B>').gsub(/"ccc"/, '<"CCC">')
    @options  = "-I #{dir}"
    #
    begin
      _test()
    ensure
      File.unlink filename if test(?f, filename)
      FileUtils.rm_r dir if test(?d, dir)
    end
  end


  def test_require1   # -r
    dir = 'foo'
    lib = 'bar'
    Dir.mkdir dir unless test(?d, dir)
    filename = "#{dir}/#{lib}.rb"
    File.open(filename, 'w') do |f|
      f.write <<-'END'
        def escape(str)
          return "<#{str.upcase}>"
        end
      END
    end
    #
    @input    = INPUT.gsub(/<%= item %>/, '<%= escape(item) %>')
    @expected = OUTPUT.gsub(/<aaa>/, '<<AAA>>').gsub(/b\&b/, '<B&B>').gsub(/"ccc"/, '<"CCC">')
    @options  = "-I #{dir} -r #{lib}"
    #
    begin
      _test()
    ensure
      File.unlink filename if test(?f, filename)
      FileUtils.rm_r dir if test(?d, dir)
    end
  end


  def test_enhancers1 # -E
    @input   = <<END
<% list = %w[<aaa> b&b "ccc"] %>
% for item in list
 - <%= item %> : <%== item %>
 - [= item =] : [== item =]
% end
END
    @expected = <<END
 - &lt;aaa&gt; : <aaa>
 - &lt;aaa&gt; : <aaa>
 - b&amp;b : b&b
 - b&amp;b : b&b
 - &quot;ccc&quot; : "ccc"
 - &quot;ccc&quot; : "ccc"
END
    @options = "-E Escape,PercentLine,HeaderFooter,BiPattern"
    _test()
  end


  def test_bodyonly1  # -b
    @input = INPUT
    @expected = SRC.sub(/\A_buf = '';/,'').sub(/\n_buf.to_s\n\z/,'')
    @options = '-b -x'
    _test()
  end


  def test_escape1  # -e
    @input = INPUT
    @expected = SRC.gsub(/<< \((.*?)\).to_s;/, '<< Erubis::XmlHelper.escape_xml(\1);')
    @options = '-ex'
    _test()
  end


  def test_invalid_option  # -1 (invalid option)
    @input = INPUT
    @options = '-1'
    _error_test(Erubis::CommandOptionError, "-1: unknown option.")
  end


  def test_invalid_enhancer  # -E hoge
    @options = '-E hoge'
    errmsg = "hoge: no such Enhancer (try '-h' to show all enhancers)."
    _error_test(Erubis::CommandOptionError, errmsg)
  end


  def test_invalid_lang  # -l hoge
    @options = '-l hoge'
    errmsg = "-l hoge: invalid language name (class Erubis::Ehoge not found)."
    _error_test(Erubis::CommandOptionError, errmsg)
  end


  def test_missing_argument  # -E
    @filename = false
    @options = '-E'
    _error_test(Erubis::CommandOptionError, "-E: enhancers required.")
    @options = '-l'
    _error_test(Erubis::CommandOptionError, "-l: lang required.")
  end


  def test_pi1  # --pi -x
    @input = PI_INPUT
    @expected = PI_SRC
    @options = '-x --pi'
    _test()
  end

  def test_pi2  # --pi -x --escape=false
    @input = PI_INPUT
    @expected = PI_ESCAPED_SRC
    @options = '-x --pi --escape=false'
    _test()
  end

  def test_pi3  # --pi
    @input = PI_INPUT
    @expected = PI_OUTPUT
    @options = '--pi'
    _test()
  end

  def test_pi4  # --pi --escape=false
    @input = PI_INPUT
    @expected = PI_ESCAPED_OUTPUT
    @options = '--pi --escape=false'
    _test()
  end

  def test_pi5  # --pi=ruby -x
    @input = PI_INPUT.gsub(/<\?rb/, '<?ruby')
    @expected = PI_SRC
    @options = '--pi=ruby -x'
    _test()
  end

  def test_pi6  # --pi -xl java
    @input = <<'END'
<?java for (int i = 0; i < arr.length; i++) { ?>
  - @{arr[i]}@ / @!{arr[i]}@
<?java } ?>
END
    @expected = <<'END'
StringBuffer _buf = new StringBuffer(); for (int i = 0; i < arr.length; i++) { 
_buf.append("  - "); _buf.append(escape(arr[i])); _buf.append(" / "); _buf.append(arr[i]); _buf.append("\n");
 } 
return _buf.toString();
END
    @options = '--pi -xl java'
    _test()
  end


  self.post_definition()

end
