##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

require "#{File.dirname(__FILE__)}/test.rb"

require 'stringio'

require 'erubis'
require 'erubis/engine/enhanced'
require 'erubis/engine/optimized'


class EnhancersTest < Test::Unit::TestCase

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
      #if @klass == Erubis::TinyEruby
      #  eruby = @klass.new(@input)
      #else
        eruby = @klass.new(@input, @options)
      #end
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


  self.post_definition()

end

__END__

##
- name:  basic1
  class: Eruby
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

- name:  xml1
  class: XmlEruby
  input: |
      <pre>
       <% for item in list %>
        <%= item %>
        <%== item %>
       <% end %>
      </pre>
  src: |
      _buf = ''; _buf << '<pre>
      ';  for item in list 
       _buf << '  '; _buf << Erubis::XmlHelper.escape_xml( item ); _buf << '
      '; _buf << '  '; _buf << ( item ).to_s; _buf << '
      ';  end 
       _buf << '</pre>
      ';
      _buf.to_s
  output: |
      <pre>
        &lt;aaa&gt;
        <aaa>
        b&amp;b
        b&b
        &quot;ccc&quot;
        "ccc"
      </pre>

##
- name:  xml2
  class: XmlEruby
  testopt:  skip_output
  input: |
      <% for item in list %>
        <%= item["var#{n}"] %>
        <%== item["var#{n}"] %>
        <%=== item["var#{n}"] %>
        <%==== item["var#{n}"] %>
      <% end %>
  src: |
      _buf = ''; for item in list 
       _buf << '  '; _buf << Erubis::XmlHelper.escape_xml( item["var#{n}"] ); _buf << '
      '; _buf << '  '; _buf << ( item["var#{n}"] ).to_s; _buf << '
      '; _buf << '  '; $stderr.puts("*** debug: item[\"var\#{n}\"]=#{(item["var#{n}"]).inspect}"); _buf << '
      '; _buf << '  '; _buf << '
      '; end 
      _buf.to_s
  output: |

##
- name:  printout1
  class: PrintOutEruby
  testopt:  print
  input: *basic1_input
  src: |4
       print '<ul>
      ';  for item in list 
       print '  <li>'; print(( item ).to_s); print '</li>
      ';  end 
       print '</ul>
      ';
  output: *basic1_output

##
- name:  printenabled1
  class: PrintEnabledEruby
  input: &printenabled1_input|
      <ul>
       <% for item in list %>
        <li><% print item %></li>
       <% end %>
      </ul>
  src: |
      @_buf = _buf = ''; _buf << '<ul>
      ';  for item in list 
       _buf << '  <li>'; print item ; _buf << '</li>
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
- name:  stdout1
  class: StdoutEruby
  testopt: stdout
  input: *basic1_input
#      <ul>
#       <% for item in list %>
#        <li><%= item %></li>
#       <% end %>
#      </ul>
  src: |
      _buf = $stdout; _buf << '<ul>
      ';  for item in list 
       _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>
      ';  end 
       _buf << '</ul>
      ';
      ''
  output: *basic1_output
#      <ul>
#        <li><aaa></li>
#        <li>b&b</li>
#        <li>"ccc"</li>
#      </ul>

##
- name:  array1
  class: ArrayEruby
  input: |
      <ul>
       <% for item in list %>
        <li><%= item %></li>
       <% end %>
      </ul>
  src: |
      _buf = []; _buf << '<ul>
      ';  for item in list 
       _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>
      ';  end 
       _buf << '</ul>
      ';
      _buf
  output:
      - "<ul>\n"
      - "  <li>"
      - "<aaa>"
      - "</li>\n"
      - "  <li>"
      - "b&b"
      - "</li>\n"
      - "  <li>"
      - "\"ccc\""
      - "</li>\n"
      - "</ul>\n"

##
- name:  arraybuffer1
  class: ArrayBufferEruby
  input: *basic1_input
  src: |
      _buf = []; _buf << '<ul>
      ';  for item in list 
       _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>
      ';  end 
       _buf << '</ul>
      ';
      _buf.join
  output: *basic1_output

- name:  stringbuffer1
  class: StringBufferEruby
  input: *basic1_input
#      <ul>
#       <% for item in list %>
#        <li><%= item %></li>
#       <% end %>
#      </ul>
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
- name:  erbout1
  class: ErboutEruby
  input: *basic1_input
  src: |
      _erbout = _buf = ''; _buf << '<ul>
      ';  for item in list 
       _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>
      ';  end 
       _buf << '</ul>
      ';
      _buf.to_s
  output: *basic1_output

##
- name:  stringio1
  class: StringIOEruby
  input: *basic1_input
  src: |
      _buf = StringIO.new; _buf << '<ul>
      ';  for item in list 
       _buf << '  <li>'; _buf << ( item ).to_s; _buf << '</li>
      ';  end 
       _buf << '</ul>
      ';
      _buf.string
  output: *basic1_output

##
- name:  notext1
  class: NoTextEruby
  input: *basic1_input
  src: |
      _buf = '';
        for item in list 
             _buf << ( item ).to_s;
        end 
      
      _buf.to_s
  output:  '<aaa>b&b"ccc"'


##
- name:  nocode1
  class: NoCodeEruby
  testopt: skip_output
  input: *basic1_input
  src: |
      <ul>

        <li></li>

      </ul>
  output: 

##
- name:  simplified
  class: SimplifiedEruby
  input: |
      <ul>
       <% for item in list %>
        <li>
         <%= item %>
        </li>
       <% end %>
      </ul>
  src: |
      _buf = ''; _buf << '<ul>
       '; for item in list ; _buf << '
        <li>
         '; _buf << ( item ).to_s; _buf << '
        </li>
       '; end ; _buf << '
      </ul>
      ';
      _buf.to_s
  output: |
      <ul>
      ^
        <li>
         <aaa>
        </li>
      ^
        <li>
         b&b
        </li>
      ^
        <li>
         "ccc"
        </li>
      ^
      </ul>

##
- name:  bipattern1
  class: BiPatternEruby
  #options: { :bipattern : '\[= =\]' }
  input: |
      <% for item in list %>
        <%= item %> % <%== item %>
        [= item =] = [== item =]
      <% end %>
  src: |
      _buf = ''; for item in list 
       _buf << '  '; _buf << ( item ).to_s; _buf << ' % '; _buf << Erubis::XmlHelper.escape_xml( item ); _buf << '
      '; _buf << '  '; _buf << ( item ).to_s; _buf << ' = '; _buf << Erubis::XmlHelper.escape_xml( item ); _buf << '
      '; end 
      _buf.to_s
  output: |4
        <aaa> % &lt;aaa&gt;
        <aaa> = &lt;aaa&gt;
        b&b % b&amp;b
        b&b = b&amp;b
        "ccc" % &quot;ccc&quot;
        "ccc" = &quot;ccc&quot;

##
- name:  bipattern2
  class: BiPatternEruby
  options:  { :bipattern: '\$\{ \}' }
  input: |
      <% for item in list %>
        <%=item%> % <%==item%>
        ${item} = ${=item}
      <% end %>
  src: |
      _buf = ''; for item in list 
       _buf << '  '; _buf << (item).to_s; _buf << ' % '; _buf << Erubis::XmlHelper.escape_xml(item); _buf << '
      '; _buf << '  '; _buf << (item).to_s; _buf << ' = '; _buf << Erubis::XmlHelper.escape_xml(item); _buf << '
      '; end 
      _buf.to_s
  output: |4
        <aaa> % &lt;aaa&gt;
        <aaa> = &lt;aaa&gt;
        b&b % b&amp;b
        b&b = b&amp;b
        "ccc" % &quot;ccc&quot;
        "ccc" = &quot;ccc&quot;

##
- name:  percentline1
  class: PercentLineEruby
  options:
  input: |
      <table>
      % for item in list
        <tr>
          <td><%= item %></td>
          <td><%== item %></td>
        </tr>
      % end
      </table>
      <pre>
      %% double percent
       % spaced percent
      </pre>
  src: |
      _buf = ''; _buf << '<table>
      '; for item in list
       _buf << '  <tr>
          <td>'; _buf << ( item ).to_s; _buf << '</td>
          <td>'; _buf << Erubis::XmlHelper.escape_xml( item ); _buf << '</td>
        </tr>
      '; end
       _buf << '</table>
      <pre>
      % double percent
       % spaced percent
      </pre>
      ';
      _buf.to_s
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
      <pre>
      % double percent
       % spaced percent
      </pre>

##
- name:  prefixedline1
  class: PrefixedLineEruby
  options: { :prefixchar: '!' }
  input: |
      <table>
        ! for item in list
        <tr>
          <td><%= item %></td>
          <td><%== item %></td>
        </tr>
        ! end
      </table>
      <pre>
        !! doubled characters
      </pre>
  src: |
      _buf = ''; _buf << '<table>
      ';   for item in list
       _buf << '  <tr>
          <td>'; _buf << ( item ).to_s; _buf << '</td>
          <td>'; _buf << Erubis::XmlHelper.escape_xml( item ); _buf << '</td>
        </tr>
      ';   end
       _buf << '</table>
      <pre>
        ! doubled characters
      </pre>
      ';
      _buf.to_s
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
      <pre>
        ! doubled characters
      </pre>

##
- name:  headerfooter1
  class: HeaderFooterEruby
  options:
  testopt:  eval('ordered_list(list)')
  input: |
      <!--#header:
      def ordered_list(list)
      #-->
      <ol>
        <% for item in list %>
        <li><%==item%></li>
        <% end %>
      </ol>
      <!--#footer: end #-->
  src: |4
      
      def ordered_list(list)
      
      _buf = ''; _buf << '<ol>
      ';   for item in list 
       _buf << '  <li>'; _buf << Erubis::XmlHelper.escape_xml(item); _buf << '</li>
      ';   end 
       _buf << '</ol>
      ';
      _buf.to_s
       end 
  output: |
      <ol>
        <li>&lt;aaa&gt;</li>
        <li>b&amp;b</li>
        <li>&quot;ccc&quot;</li>
      </ol>

##
- name:  deleteindent1
  class: DeleteIndentEruby
  options:
  testopt:
  input: *basic1_input
  src: |
      _buf = ''; _buf << '<ul>
      '; for item in list 
       _buf << '<li>'; _buf << ( item ).to_s; _buf << '</li>
      '; end 
       _buf << '</ul>
      ';
      _buf.to_s
  output: |
      <ul>
      <li><aaa></li>
      <li>b&b</li>
      <li>"ccc"</li>
      </ul>

##
- name:  interpolation1
  class: InterpolationEruby
  options:
  testopt:
  input: *basic1_input
  src: |
      _buf = ''; _buf << %Q`<ul>\n`
        for item in list 
       _buf << %Q`  <li>#{ item }</li>\n`
        end 
       _buf << %Q`</ul>\n`
      _buf.to_s
  output: *basic1_output

- name:  interpolation2
  desc:  sharp, back-quote, and backslash should be escaped, but other quotes should not be escaped (reported by andrewj)
  class: InterpolationEruby
  options:
  testopt:
  input: |
      <p>`back-quote`</p>
      <p><%= `echo back-tick operator` %></p>
      <p>#{sharp}</p>
      <p>'single quote'</p>
      <p>"double quote"</p>
      <p>backslash\n\t</p>
  src: |
      _buf = ''; _buf << %Q`<p>\`back-quote\`</p>
      <p>#{ `echo back-tick operator` }</p>
      <p>\#{sharp}</p>
      <p>'single quote'</p>
      <p>"double quote"</p>
      <p>backslash\\n\\t</p>\n`
      _buf.to_s
  output: |
      <p>`back-quote`</p>
      <p>back-tick operator
      </p>
      <p>#{sharp}</p>
      <p>'single quote'</p>
      <p>"double quote"</p>
      <p>backslash\n\t</p>
