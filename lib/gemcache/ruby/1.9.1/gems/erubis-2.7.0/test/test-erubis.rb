##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

require "#{File.dirname(__FILE__)}/test.rb"

require 'stringio'

require 'erubis'
require 'erubis/engine/enhanced'
require 'erubis/engine/optimized'
require 'erubis/tiny'


class ErubisTest < Test::Unit::TestCase

  testdata_list = load_yaml_datafile(__FILE__)
  define_testmethods(testdata_list)


  def _test()
    @src.gsub!(/\^/, ' ')
    @output.gsub!(/\^/, ' ') if @output.is_a?(String)
    if @class
      k = Erubis
      @class.split('::').each do |name| k = k.const_get(name) end
      @klass = k
    else
      @klass = Erubis::Eruby
    end
    @options ||= {}
    @chomp.each do |target|
      case target
      when 'src'      ;  @src.chomp!
      when 'input'    ;  @input.chomp!
      when 'expected' ;  @expected.chomp!
      else
        raise "#{@name}: invalid chomp value: #{@chomp.inspect}"
      end
    end if @chomp

    if @testopt == 'load_file'
      filename = "tmp.#{@name}.eruby"
      begin
        File.open(filename, 'w') { |f| f.write(@input) }
        eruby = @klass.load_file(filename, @options)
      ensure
        cachename = filename + '.cache'
        File.unlink(cachename) if test(?f, cachename)
        File.unlink(filename) if test(?f, filename)
      end
    else
      if @klass == Erubis::TinyEruby
        eruby = @klass.new(@input)
      else
        eruby = @klass.new(@input, @options)
      end
    end
    assert_text_equal(@src, eruby.src)

    return if @testopt == 'skip_output'

    list = ['<aaa>', 'b&b', '"ccc"']
    context = @testopt == 'context' ? Erubis::Context.new : {}
    context[:list] = list

    case @testopt
    when /\Aeval\(/
      eval eruby.src
      actual = eval @testopt
      assert_text_equal(@output, actual)
    when 'stdout', 'print'
      begin
        orig = $stdout
        $stdout = stringio = StringIO.new
        #actual = eruby.evaluate(context)
        actual = eruby.result(context)
      ensure
        $stdout = orig
      end
      if @testopt == 'stdout'
        assert_equal("", actual)
      else
        assert_nil(actual)
      end
      assert_text_equal(@output, stringio.string)
    when 'evaluate', 'context'
      actual = eruby.evaluate(context)
      assert_text_equal(@output, actual)
    when 'binding'
      actual = eruby.result(binding())
      assert_text_equal(@output, actual)
    else
      actual = eruby.result(context)
      assert_text_equal(@output, actual)
    end
  end


  def test_load_file_cache1
    @input = <<END
<ul>
<% for item in @list %>
  <li><%= item %></li>
<% end %>
</ul>
END
    @src = <<END
_buf = ''; _buf << '<ul>
'; for item in @list 
 _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>
'; end 
 _buf << '</ul>
';
_buf.to_s
END
    @klass = Erubis::Eruby
    filename = 'tmp.load_file_timestamp1'
    cachename = filename + '.cache'
    begin
      ## when cache doesn't exist then it is created automatically
      File.open(filename, 'w') { |f| f.write(@input) }
      mtime = Time.now - 2.0
      File.utime(mtime, mtime, filename)
      !test(?f, cachename)  or raise "** failed"
      engine = @klass.load_file(filename)
      assert_block() { test(?f, cachename) }
      assert_block() { File.mtime(filename) <= File.mtime(cachename) }
      assert_text_equal(@src, engine.src)
      ## when cache has different timestamp then it is recreated
      input2 = @input.gsub(/ul>/, 'ol>')
      src2   = @src.gsub(/ul>/, 'ol>')
      File.open(filename, 'w') { |f| f.write(input2) }
      t1 = Time.now()
      sleep(1)
      t2 = Time.now()
      #
      File.utime(t1, t1, filename)
      File.utime(t2, t2, cachename)
      File.mtime(filename) < File.mtime(cachename)  or raise "** failed"
      engine = @klass.load_file(filename)
      assert_block('cache should have same timestamp') { File.mtime(filename) == File.mtime(cachename) }
      #assert_text_equal(@src, engine.src)
      assert_text_equal(src2, engine.src)
      #
      File.utime(t2, t2, filename)
      File.utime(t1, t1, cachename)
      File.mtime(filename) > File.mtime(cachename)  or raise "** failed"
      engine = @klass.load_file(filename)
      assert_block('cache should have same timestamp') { File.mtime(filename) == File.mtime(cachename) }
      assert_text_equal(src2, engine.src)
    ensure
      File.unlink(cachename) if File.file?(cachename)
      File.unlink(filename) if File.file?(filename)
    end
  end


  class Dummy
  end

  def _class_has_instance_method(klass, method)
    return klass.instance_methods.collect{|m| m.to_s}.include?(method.to_s)
  end

  def test_def_method1
    s = "<%for i in list%>i=<%=i%>\n<%end%>"
    eruby = Erubis::Eruby.new(s)
    assert(! _class_has_instance_method(Dummy, 'render'))
    eruby.def_method(Dummy, 'render(list)', 'foo.rhtml')
    assert(_class_has_instance_method(Dummy, 'render'))
    actual = Dummy.new().render(%w[1 2 3])
    assert_equal("i=1\ni=2\ni=3\n", actual)
  end

  def test_def_method2
    s = "<%for i in list%>i=<%=i%>\n<%end%>"
    eruby = Erubis::Eruby.new(s)
    assert(! (eruby.respond_to? :render))
    eruby.def_method(eruby, 'render(list)', 'foo.rhtml')
    assert eruby.respond_to?(:render)
    actual = eruby.render([1, 2, 3])
    assert_equal("i=1\ni=2\ni=3\n", actual)
    assert(! _class_has_instance_method(eruby.class, 'render'))
  end

  def test_evaluate_creates_proc
    s = "hello <%= @name %>"
    eruby = Erubis::Eruby.new(s)
    assert_nil(eruby.instance_variable_get('@_proc'))
    actual1 = eruby.evaluate(:name=>'world')
    assert_not_nil(eruby.instance_variable_get('@_proc'))
    assert_instance_of(Proc, eruby.instance_variable_get('@_proc'))
    actual2 = eruby.evaluate(:name=>'world')
    assert_equal(actual1, actual2)
    # convert() must clear @_proc
    eruby.convert(s)
    assert_nil(eruby.instance_variable_get('@_proc'))
  end

  #def test_toplevel_binding
  #  s = "locals = <%= local_variables().inspect %>\n<% x = 50 %>\n"
  #  eruby = Erubis::Eruby.new(s)
  #  _x = eval 'x', TOPLEVEL_BINDING
  #  _y = eval 'y', TOPLEVEL_BINDING
  #  actual = eruby.evaluate(:x=>_x, :y=>_y)
  #  _x = eval 'x', TOPLEVEL_BINDING
  #  _y = eval 'y', TOPLEVEL_BINDING
  #  puts "*** actual=#{actual.inspect}, x=#{_x.inspect}, y=#{_y.inspect}"
  #end

  self.post_definition()

end

x = 10
y = 20


__END__
- name:  basic1
  input: &basic1_input|
      <ul>
       <% for item in list %>
        <li><%= item %></li>
       <% end %>
      </ul>
  src: &basic1_src|
      _buf = ''; _buf << '<ul>
      ';  for item in list 
       _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>
      ';  end 
       _buf << '</ul>
      ';
      _buf.to_s
  output: &basic1_output|
      <ul>
        <li><aaa></li>
        <li>b&b</li>
        <li>"ccc"</li>
      </ul>

##
- name:  basic2
  input: |
      <ul>
        <% i = 0
           for item in list
             i += 1
         %>
        <li><%= item %></li>
        <% end %>
      </ul>
  src: |
      _buf = ''; _buf << '<ul>
      ';   i = 0
           for item in list
             i += 1
      ^^^
       _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>
      ';   end 
       _buf << '</ul>
      ';
      _buf.to_s
  output: *basic1_output
#      <ul>
#        <li><aaa></li>
#        <li>b&b</li>
#        <li>"ccc"</li>
#      </ul>

##
- name:  basic3
  input: |
      <ul><% i = 0
          for item in list
            i += 1 %><li><%= item %></li><% end %>
      </ul>
  src: |
      _buf = ''; _buf << '<ul>'; i = 0
          for item in list
            i += 1 ; _buf << '<li>'; _buf << ( item ).to_s; _buf << '</li>'; end ; _buf << '
      '; _buf << '</ul>
      ';
      _buf.to_s
  output: |
      <ul><li><aaa></li><li>b&b</li><li>"ccc"</li>
      </ul>

##
- name:  context1
  testopt:  context
  input: |
      <ul>
       <% for item in @list %>
        <li><%= item %></li>
       <% end %>
      </ul>
  src: |
      _buf = ''; _buf << '<ul>
      ';  for item in @list 
       _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>
      ';  end 
       _buf << '</ul>
      ';
      _buf.to_s
  output: *basic1_output

##
- name:  ignore1
  input: |
      <ul>
       <%# i = 0 %>
       <% for item in list %>
        <%#
           i += 1
           color = i % 2 == 0 ? '#FFCCCC' : '#CCCCFF'
         %>
        <li>  <%#= i %>  :  <%= item %>  </li>
       <% end %>
      </ul>
  src: |
      _buf = ''; _buf << '<ul>
      ';
        for item in list 
      
      
      
      
       _buf << '  <li>  ';; _buf << '  :  '; _buf << ( item ).to_s; _buf << '  </li>
      ';  end 
       _buf << '</ul>
      ';
      _buf.to_s
  output: |
      <ul>
        <li>    :  <aaa>  </li>
        <li>    :  b&b  </li>
        <li>    :  "ccc"  </li>
      </ul>

##
- name:  quotation1
  desc:  single quotation and backslash
  class: Eruby
  input: &quotation1_input|
      a = "'"
      b = "\""
      c = '\''
  src: |
      _buf = ''; _buf << 'a = "\'"
      b = "\\""
      c = \'\\\'\'
      ';
      _buf.to_s
  output: *quotation1_input

##
- name:  minus1
  desc:  '<%- -%>'
  class: Eruby
  input: |
      <ul>
       <%- for item in list -%>
        <li><%= item -%></li>
       <% end -%>
      </ul>
  src: *basic1_src
  output: *basic1_output

##
- name:  pattern1
  options:
      :pattern : '\[@ @\]'
  input: |
      <ul>
       [@ for item in list @]
        <li>[@= item @]</li>
       [@ end @]
      </ul>
  src: |
      _buf = ''; _buf << '<ul>
      ';  for item in list 
       _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>
      ';  end 
       _buf << '</ul>
      ';
      _buf.to_s
  output: *basic1_output
#      <ul>
#        <li><aaa></li>
#        <li>b&b</li>
#        <li>"ccc"</li>
#      </ul>

##
- name:  pattern2
  options:
      :pattern : '<(?:!--)?% %(?:--)?>'
  input: |
      <ul>
       <!--% for item in list %-->
        <li><%= item %></li>
       <!--% end %-->
      </ul>
  src: |
      _buf = ''; _buf << '<ul>
      ';  for item in list 
       _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>
      ';  end 
       _buf << '</ul>
      ';
      _buf.to_s
  output: *basic1_output
#      <ul>
#        <li><aaa></li>
#        <li>b&b</li>
#        <li>"ccc"</li>
#      </ul>

##
- name:  trim1
  options:
      :trim : false
  input: *basic1_input
#      <ul>
#       <% for item in list %>
#        <li><%= item %></li>
#       <% end %>
#      </ul>
  src: |
      _buf = ''; _buf << '<ul>
      '; _buf << ' '; for item in list ; _buf << '
      '; _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>
      '; _buf << ' '; end ; _buf << '
      '; _buf << '</ul>
      ';
      _buf.to_s
  output: |
      <ul>
      ^
        <li><aaa></li>
      ^
        <li>b&b</li>
      ^
        <li>"ccc"</li>
      ^
      </ul>

##
- name:  bodyonly1
  testopt:  skip_output
  options: { :preamble: no, :postamble: no }
  input: *basic1_input
  src: |4
       _buf << '<ul>
      ';  for item in list 
       _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>
      ';  end 
       _buf << '</ul>
      ';
  chomp:  [src]
  expected: null

##
- name:  loadfile1
  testopt: load_file
  #input: |
  #    <ul>
  #     <% for item in list %>
  #      <li><%= item %></li>
  #     <% end %>
  #    </ul>
  input:
      "<ul>\r\n <% for item in list %>\r\n  <li><%= item %></li>\r\n <% end %>\r\n</ul>\r\n"
  #src: |
  #    _buf = ''; _buf << "<ul>\n"
  #      for item in list
  #    _buf << "  <li>"; _buf << ( item ).to_s; _buf << "</li>\n"
  #      end
  #    _buf << "</ul>\n"
  #    _buf
  src:
    "_buf = ''; _buf << '<ul>\r\n';  for item in list \r\n _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>\r\n';  end \r\n _buf << '</ul>\r\n';\n_buf.to_s\n"
  #output: |
  #    <ul>
  #      <li><aaa></li>
  #      <li>b&b</li>
  #      <li>"ccc"</li>
  #    </ul>
  output:
      "<ul>\n  <li><aaa></li>\n  <li>b&b</li>\n  <li>\"ccc\"</li>\n</ul>\n"
  #    "<ul>\r\n  <li><aaa></li>\r\n  <li>b&b</li>\r\n  <li>\"ccc\"</li>\r\n</ul>\r\n"

##
- name:  nomatch1
  desc:  bug
  input: &nomatch1|
      <ul>
        <li>foo</li>
      </ul>
  src: |
      _buf = ''; _buf << '<ul>
        <li>foo</li>
      </ul>
      ';
      _buf.to_s
  output: *nomatch1

##
- name:  escape1
  options: { :escape: true }
  input: |
      <% str = '<>&"' %>
      <%= str %>
      <%== str %>
  src: |
      _buf = ''; str = '<>&"' 
       _buf << Erubis::XmlHelper.escape_xml( str ); _buf << '
      '; _buf << ( str ).to_s; _buf << '
      ';
      _buf.to_s
  output: |
      &lt;&gt;&amp;&quot;
      <>&"

##
- name:  tailch1
  options:
  input: |
        <p>
          <% str = '<>&"' %>
          <%= str %>
          <%= str =%>
          <%= str -%>
        </p>
  src: |
        _buf = ''; _buf << '<p>
        ';   str = '<>&"' 
         _buf << '  '; _buf << ( str ).to_s; _buf << '
        '; _buf << '  '; _buf << ( str ).to_s; _buf << '  '; _buf << ( str ).to_s; _buf << '</p>
        ';
        _buf.to_s
  output: |
        <p>
          <>&"
          <>&"  <>&"</p>

##
- name:  doublepercent1
  options:
  input: |
        <% x1 = 10 %>
        <%% x2 = 20 %>
        <%= x1 %>
        <%%= x2 %>
  src: |
        _buf = ''; x1 = 10 
         _buf << '<% x2 = 20 %>
        '; _buf << ( x1 ).to_s; _buf << '
        '; _buf << '<%= x2 %>
        ';
        _buf.to_s
  output: |
        <% x2 = 20 %>
        10
        <%= x2 %>

##
- name:  optimized1
  class: OptimizedEruby
  input: &optimized1_input|
      <table>
       <% for item in list %>
        <tr>
          <td><%= item %></td>
          <td><%== item %></td>
        </tr>
       <% end %>
      </table>
      <ul><% for item in list %><li><%= item %></li><% end %></ul>
  src: |
      _buf = '<table>
      ';  for item in list 
       _buf << '  <tr>
          <td>' << ( item ).to_s << '</td>
          <td>' << Erubis::XmlHelper.escape_xml( item ) << '</td>
        </tr>
      ';  end 
       _buf << '</table>
      <ul>'; for item in list ; _buf << '<li>' << ( item ).to_s << '</li>'; end ; _buf << '</ul>
      '
      _buf
  output: |
      <table>
        <tr>
          <td><aaa></td>
          <td>&lt;aaa&gt;</td>
        </tr>
        <tr>
          <td>b&b</td>
          <td>b&amp;b</td>
        </tr>
        <tr>
          <td>"ccc"</td>
          <td>&quot;ccc&quot;</td>
        </tr>
      </table>
      <ul><li><aaa></li><li>b&b</li><li>"ccc"</li></ul>

##
- name:  optimized2
  class: OptimizedXmlEruby
  input: *optimized1_input
#      <table>
#       <% for item in list %>
#        <tr>
#          <td><%= item %></td>
#          <td><%== item %></td>
#        </tr>
#       <% end %>
#      </table>
#      <ul><% for item in list %><li><%= item %></li><% end %></ul>
  src: |
      _buf = '<table>
      ';  for item in list 
       _buf << '  <tr>
          <td>' << Erubis::XmlHelper.escape_xml( item ) << '</td>
          <td>' << ( item ).to_s << '</td>
        </tr>
      ';  end 
       _buf << '</table>
      <ul>'; for item in list ; _buf << '<li>' << Erubis::XmlHelper.escape_xml( item ) << '</li>'; end ; _buf << '</ul>
      '
      _buf
  output: |
      <table>
        <tr>
          <td>&lt;aaa&gt;</td>
          <td><aaa></td>
        </tr>
        <tr>
          <td>b&amp;b</td>
          <td>b&b</td>
        </tr>
        <tr>
          <td>&quot;ccc&quot;</td>
          <td>"ccc"</td>
        </tr>
      </table>
      <ul><li>&lt;aaa&gt;</li><li>b&amp;b</li><li>&quot;ccc&quot;</li></ul>

##
- name:  optimized3
  desc:  bug
  class: OptimizedEruby
  input: |
      user = <%= "Foo" %>
      <% for item in list %>
        <%= item %>
      <% end %>
  src: |
      _buf = 'user = '; _buf << ( "Foo" ).to_s << '
      '; for item in list 
       _buf << '  ' << ( item ).to_s << '
      '; end 

      _buf
  output: |
      user = Foo
        <aaa>
        b&b
        "ccc"

##
- name:  optimized4
  desc:  single quotation and backslash
  class: OptimizedEruby
  input: &optimized4_input|
      a = "'"
      b = "\""
      c = '\''
  src: |
      _buf = 'a = "\'"
      b = "\\""
      c = \'\\\'\'
      ';
      _buf
  output: *optimized4_input

##
- name:  tiny1
  class: TinyEruby
  testopt:  binding
  input: |
      <ul>
       <% for item in list %>
        <li><%= item %></li>
       <% end %>
      </ul>
  src: |
      _buf = ''; _buf << '<ul>
       '; for item in list ; _buf << '
        <li>'; _buf << ( item ).to_s; _buf << '</li>
       '; end ; _buf << '
      </ul>
      ';
      _buf.to_s
  output: |
      <ul>
      ^
        <li><aaa></li>
      ^
        <li>b&b</li>
      ^
        <li>"ccc"</li>
      ^
      </ul>

##
- name:  tiny2
  class: TinyEruby
  testopt:  evaluate
  input: |
      <ul>
       <% for item in @list %>
        <li><%= item %></li>
       <% end %>
      </ul>
  src: |
      _buf = ''; _buf << '<ul>
       '; for item in @list ; _buf << '
        <li>'; _buf << ( item ).to_s; _buf << '</li>
       '; end ; _buf << '
      </ul>
      ';
      _buf.to_s
  output: |
      <ul>
      ^
        <li><aaa></li>
      ^
        <li>b&b</li>
      ^
        <li>"ccc"</li>
      ^
      </ul>

##
- name:  pi1
  class:  PI::Eruby
  testopt:  evaluate
  input: &input_pi1|
      <ul>
       <?rb for item in @list ?>
        <li>@{item}@ / @!{item}@</li>
        <li><%= item %> / <%== item %></li>
       <?rb end ?>
      </ul>
  src: &src_pi1|
      _buf = ''; _buf << '<ul>
      ';  for item in @list 
       _buf << '  <li>'; _buf << Erubis::XmlHelper.escape_xml(item); _buf << ' / '; _buf << (item).to_s; _buf << '</li>
        <li>'; _buf << ( item ).to_s; _buf << ' / '; _buf << Erubis::XmlHelper.escape_xml( item ); _buf << '</li>
      ';  end 
       _buf << '</ul>
      ';
      _buf.to_s
  output: &output_pi1|
      <ul>
        <li>&lt;aaa&gt; / <aaa></li>
        <li><aaa> / &lt;aaa&gt;</li>
        <li>b&amp;b / b&b</li>
        <li>b&b / b&amp;b</li>
        <li>&quot;ccc&quot; / "ccc"</li>
        <li>"ccc" / &quot;ccc&quot;</li>
      </ul>

##
- name:  pi2
  class:  PI::Eruby
  options: { :escape: false }
  testopt:  evaluate
  input: *input_pi1
  src: |
      _buf = ''; _buf << '<ul>
      ';  for item in @list 
       _buf << '  <li>'; _buf << (item).to_s; _buf << ' / '; _buf << Erubis::XmlHelper.escape_xml(item); _buf << '</li>
        <li>'; _buf << Erubis::XmlHelper.escape_xml( item ); _buf << ' / '; _buf << ( item ).to_s; _buf << '</li>
      ';  end 
       _buf << '</ul>
      ';
      _buf.to_s
  output: |
      <ul>
        <li><aaa> / &lt;aaa&gt;</li>
        <li>&lt;aaa&gt; / <aaa></li>
        <li>b&b / b&amp;b</li>
        <li>b&amp;b / b&b</li>
        <li>"ccc" / &quot;ccc&quot;</li>
        <li>&quot;ccc&quot; / "ccc"</li>
      </ul>

##
- name:  pi3
  class:  PI::Eruby
  options: { :pi: hoge, :embchar: '$' }
  testopt:  evaluate
  input: |
      <ul>
       <?hoge for item in @list ?>
        <li>${item}$ / $!{item}$</li>
        <li><%= item %> / <%== item %></li>
       <?hoge end ?>
      </ul>
  src: *src_pi1
  output: *output_pi1

- name:  pi4
  class:  PI::Eruby
  testopt: evaluate
  input: |
      <?rb-header
        def show(list)
      ?>
      <ul>
       <?rb for item in list ?>
         <?rb-value item ?>
       <?rb end ?>
       <?rb-comment
       # comment
       # comment
       ?>
      </ul>
      <?rb-footer
        end
	show(@list) ?>

  src: |4
      
        def show(list)
      
      _buf = ''; _buf << '<ul>
      ';  for item in list 
       _buf << (    item 
      ).to_s;  end 
      
      
      

       _buf << '</ul>
      ';
      _buf.to_s
      
        end
	show(@list) 

  output: |
      <ul>
      <aaa>b&b"ccc"</ul>
      

- name:  pitiny1
  class:  PI::TinyEruby
  testopt: evaluate
  input: |
	<ul>
	 <?rb for item in @list ?>
	  <li>@{item}@ / @!{item}@</li>
	 <?rb end ?>
	</ul>
  src: |
	_buf = ''; _buf << '<ul>
	';  for item in @list 
	 _buf << '  <li>'; _buf << Erubis::XmlHelper.escape_xml(item); _buf << ' / '; _buf << (item).to_s; _buf << '</li>
	';  end 
	 _buf << '</ul>
	';
	_buf.to_s
  output: |
	<ul>
	  <li>&lt;aaa&gt; / <aaa></li>
	  <li>b&amp;b / b&b</li>
	  <li>&quot;ccc&quot; / "ccc"</li>
	</ul>

