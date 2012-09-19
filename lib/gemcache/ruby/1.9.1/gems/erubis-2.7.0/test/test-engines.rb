##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

require "#{File.dirname(__FILE__)}/test.rb"

require 'erubis'
require 'erubis/engine/eruby'
require 'erubis/engine/ephp'
require 'erubis/engine/ec'
require 'erubis/engine/ecpp'
require 'erubis/engine/ejava'
require 'erubis/engine/escheme'
require 'erubis/engine/eperl'
require 'erubis/engine/ejavascript'


class EnginesTest < Test::Unit::TestCase

  #load_yaml_documents(__FILE__)
  testdata_list = load_yaml_datafile(__FILE__)
  define_testmethods(testdata_list)

  def _test()
    klass = Erubis.const_get(@class)
    engine = klass.new(@input, @options || {})
    actual = engine.src
    assert_text_equal(@expected, actual)
  end


  self.post_definition()

end

__END__
- name:  ruby1
  lang:  ruby
  class: Eruby
  options:
  input: |
      <table>
       <tbody>
        <% i = 0
           list.each_with_index do |item, i| %>
        <tr>
         <td><%= i+1 %></td>
         <td><%== list %></td>
        </tr>
       <% end %>
       </tbody>
      </table>
      <%=== i+1 %>
  expected: |
      _buf = ''; _buf << '<table>
       <tbody>
      ';   i = 0
           list.each_with_index do |item, i| 
       _buf << '  <tr>
         <td>'; _buf << ( i+1 ).to_s; _buf << '</td>
         <td>'; _buf << Erubis::XmlHelper.escape_xml( list ); _buf << '</td>
        </tr>
      ';  end 
       _buf << ' </tbody>
      </table>
      '; $stderr.puts("*** debug: i+1=#{(i+1).inspect}"); _buf << '
      ';
      _buf.to_s
##
- name:  ruby2_options
  lang:  ruby
  class: Eruby
  options: { :bufvar: '@_out_buf' }
  input: |
      <table>
        <% for item in @items %>
        <tr>
          <td><%= i+1 %></td>
          <td><%== list %></td>
        </tr>
        <% end %>
      </table>
  expected: |
      @_out_buf = ''; @_out_buf << '<table>
      ';   for item in @items 
       @_out_buf << '  <tr>
          <td>'; @_out_buf << ( i+1 ).to_s; @_out_buf << '</td>
          <td>'; @_out_buf << Erubis::XmlHelper.escape_xml( list ); @_out_buf << '</td>
        </tr>
      ';   end 
       @_out_buf << '</table>
      ';
      @_out_buf.to_s
##
- name:  php1
  lang:  php
  class: Ephp
  options:
  input: |
      <table>
       <tbody>
      <%
          $i = 0;
          foreach ($list as $item) {
            $i++;
       %>
        <tr>
         <td><%= $i %></td>
         <td><%== $item %></td>
        </tr>
      <%
          }
       %>
       </tbody>
      </table>
      <%=== $i %>
  expected: |
      <table>
       <tbody>
      <?php 
          $i = 0;
          foreach ($list as $item) {
            $i++;
       ?>
        <tr>
         <td><?php echo $i; ?></td>
         <td><?php echo htmlspecialchars($item); ?></td>
        </tr>
      <?php 
          }
       ?>
       </tbody>
      </table>
      <?php error_log('*** debug: $i='.($i), 0); ?>
##
- name:  c1
  lang:  c
  class: Ec
  options: { :filename: foo.html, :indent: '  ' }
  input: |4
      <table>
       <tbody>
      <%  for (i = 0; i < list; i++) { %>
        <tr>
         <td><%= "%d", i %></td>
         <td><%== list[i] %></td>
        </tr>
      <%  } %>
       </tbody>
      </table>
      <%=== "%d", i %>
  expected: |
      #line 1 "foo.html"
        fputs("<table>\n"
              " <tbody>\n", stdout);
        for (i = 0; i < list; i++) { 
        fputs("  <tr>\n"
              "   <td>", stdout); fprintf(stdout, "%d", i); fputs("</td>\n"
              "   <td>", stdout); escape(list[i], stdout); fputs("</td>\n"
              "  </tr>\n", stdout);
        } 
        fputs(" </tbody>\n"
              "</table>\n", stdout);
         fprintf(stderr, "*** debug: i=" "%d", i); fputs("\n", stdout);
##
- name:  cpp1
  lang:  cpp
  class: Ecpp
  options: { :filename: foo.html, :indent: '  ' }
  input: |4
      <table>
       <tbody>
      <%  for (i = 0; i < n; i++) { %>
        <tr>
         <td><%= i %></td>
         <td><%== list[i] %></td>
        </tr>
      <%  } %>
       </tbody>
      </table>
      <%=== i %>
  expected: |
      #line 1 "foo.html"
        _buf << "<table>\n"
                " <tbody>\n";
        for (i = 0; i < n; i++) { 
        _buf << "  <tr>\n"
                "   <td>"; _buf << (i); _buf << "</td>\n"
                "   <td>"; escape(list[i]); _buf << "</td>\n"
                "  </tr>\n";
        } 
        _buf << " </tbody>\n"
                "</table>\n";
         std::cerr << "*** debug: i=" << (i); _buf << "\n";
##
- name:  java1
  lang:  java
  class: Ejava
  options: { :buf: _buf, :bufclass: StringBuilder, :indent: '    ' }
  input: |
      <table>
       <tbody>
      <%
          int i = 0;
          for (Iterator it = list.iterator(); it.hasNext(); ) {
              String s = (String)it.next();
              i++;
      %>
        <tr class="<%= i%2==0 ? "even" : "odd" %>">
         <td><%= i %></td>
         <td><%== s %></td>
        </tr>
      <%
          }
      %>
       <tbody>
      </table>
      <%=== i %>
  expected: |4
          StringBuilder _buf = new StringBuilder(); _buf.append("<table>\n"
                    + " <tbody>\n");
           
          int i = 0;
          for (Iterator it = list.iterator(); it.hasNext(); ) {
              String s = (String)it.next();
              i++;
             
          _buf.append("  <tr class=\""); _buf.append(i%2==0 ? "even" : "odd"); _buf.append("\">\n"
                    + "   <td>"); _buf.append(i); _buf.append("</td>\n"
                    + "   <td>"); _buf.append(escape(s)); _buf.append("</td>\n"
                    + "  </tr>\n");
           
          }
          
          _buf.append(" <tbody>\n"
                    + "</table>\n");
           System.err.println("*** debug: i="+(i)); _buf.append("\n");
          return _buf.toString();
##
- name:  scheme1
  lang:  scheme
  class: Escheme
  options:
  input: &scheme1_input|
      <% (let ((i 0)) %>
      <table>
       <tbody>
      <%
        (for-each
         (lambda (item)
           (set! i (+ i 1))
      %>
        <tr>
         <td><%= i %></td>
         <td><%== item %></td>
        </tr>
      <%
          ); lambda end
         list); for-each end
      %>
       </tbody>
      </table>
      <%=== i %>
      <% ); let end %>
  expected: |4
      (let ((_buf '())) (define (_add x) (set! _buf (cons x _buf)))  (let ((i 0)) 
      (_add "<table>
       <tbody>\n")
      
        (for-each
         (lambda (item)
           (set! i (+ i 1))
      
      (_add "  <tr>
         <td>")(_add i)(_add "</td>
         <td>")(_add (escape item))(_add "</td>
        </tr>\n")
      
          ); lambda end
         list); for-each end
      
      (_add " </tbody>
      </table>\n")
      (display "*** debug: i=")(display i)(display "\n")(_add "\n")
       ); let end 
        (reverse _buf))
  
##
- name:  scheme2
  lang:  scheme
  class: Escheme
  options: { :func: 'display' }
  input: *scheme1_input
  expected: |4
       (let ((i 0)) 
      (display "<table>
       <tbody>\n")
      
        (for-each
         (lambda (item)
           (set! i (+ i 1))
      
      (display "  <tr>
         <td>")(display i)(display "</td>
         <td>")(display (escape item))(display "</td>
        </tr>\n")
      
          ); lambda end
         list); for-each end
      
      (display " </tbody>
      </table>\n")
      (display "*** debug: i=")(display i)(display "\n")(display "\n")
       ); let end 
##
- name:  perl1
  lang:  perl
  class: Eperl
  options:
  input: |
      <%
         my $user = 'Erubis';
         my @list = ('<aaa>', 'b&b', '"ccc"');
      %>
      <p>Hello <%= $user %>!</p>
      <table>
        <tbody>
          <% $i = 0; %>
          <% for $item (@list) { %>
          <tr bgcolor=<%= ++$i % 2 == 0 ? '#FFCCCC' : '#CCCCFF' %>">
            <td><%= $i %></td>
            <td><%== $item %></td>
          </tr>
          <% } %>
        </tbody>
      </table>
      <%=== $i %>
  expected: |4
      use HTML::Entities; 
         my $user = 'Erubis';
         my @list = ('<aaa>', 'b&b', '"ccc"');
      
      print('<p>Hello '); print($user); print('!</p>
      <table>
        <tbody>
      ');      $i = 0; 
           for $item (@list) { 
      print('    <tr bgcolor='); print(++$i % 2 == 0 ? '#FFCCCC' : '#CCCCFF'); print('">
            <td>'); print($i); print('</td>
            <td>'); print(encode_entities($item)); print('</td>
          </tr>
      ');      } 
      print('  </tbody>
      </table>
      '); print('*** debug: $i=', $i, "\n");print('
      '); 
##
- name:  javascript1
  lang:  javascript
  class: Ejavascript
  options:
  input: &javascript_input |
      <%
         var user = 'Erubis';
         var list = ['<aaa>', 'b&b', '"ccc"'];
      %>
      <p>Hello <%= user %>!</p>
      <table>
        <tbody>
          <% var i; %>
          <% for (i = 0; i < list.length; i++) { %>
          <tr bgcolor=<%= ++i % 2 == 0 ? '#FFCCCC' : '#CCCCFF' %>">
            <td><%= i %></td>
            <td><%= list[i] %></td>
          </tr>
          <% } %>
        </tbody>
      </table>
      <%=== i %>
  expected: |4
      var _buf = [];
         var user = 'Erubis';
         var list = ['<aaa>', 'b&b', '"ccc"'];
      
      _buf.push("<p>Hello "); _buf.push(user); _buf.push("!</p>\n\
      <table>\n\
        <tbody>\n");
           var i; 
           for (i = 0; i < list.length; i++) { 
      _buf.push("    <tr bgcolor="); _buf.push(++i % 2 == 0 ? '#FFCCCC' : '#CCCCFF'); _buf.push("\">\n\
            <td>"); _buf.push(i); _buf.push("</td>\n\
            <td>"); _buf.push(list[i]); _buf.push("</td>\n\
          </tr>\n");
           } 
      _buf.push("  </tbody>\n\
      </table>\n");
      alert("*** debug: i="+(i)); _buf.push("\n");
      document.write(_buf.join(""));
 ##
- name:  javascript2
  lang:  javascript
  class: Ejavascript
  options: { :docwrite: false }
  input: *javascript_input
  expected: |4
      var _buf = [];
         var user = 'Erubis';
         var list = ['<aaa>', 'b&b', '"ccc"'];
      
      _buf.push("<p>Hello "); _buf.push(user); _buf.push("!</p>\n\
      <table>\n\
        <tbody>\n");
           var i; 
           for (i = 0; i < list.length; i++) { 
      _buf.push("    <tr bgcolor="); _buf.push(++i % 2 == 0 ? '#FFCCCC' : '#CCCCFF'); _buf.push("\">\n\
            <td>"); _buf.push(i); _buf.push("</td>\n\
            <td>"); _buf.push(list[i]); _buf.push("</td>\n\
          </tr>\n");
           } 
      _buf.push("  </tbody>\n\
      </table>\n");
      alert("*** debug: i="+(i)); _buf.push("\n");
      _buf.join("");
 ##
