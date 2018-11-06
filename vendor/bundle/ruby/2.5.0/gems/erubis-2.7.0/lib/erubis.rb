##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

##
## an implementation of eRuby
##
## ex.
##   input = <<'END'
##    <ul>
##     <% for item in @list %>
##      <li><%= item %>
##          <%== item %></li>
##     <% end %>
##    </ul>
##   END
##   list = ['<aaa>', 'b&b', '"ccc"']
##   eruby = Erubis::Eruby.new(input)
##   puts "--- code ---"
##   puts eruby.src
##   puts "--- result ---"
##   context = Erubis::Context.new()   # or new(:list=>list)
##   context[:list] = list
##   puts eruby.evaluate(context)
##
## result:
##   --- source ---
##   _buf = ''; _buf << '<ul>
##   ';  for item in @list 
##    _buf << '  <li>'; _buf << ( item ).to_s; _buf << '
##   '; _buf << '      '; _buf << Erubis::XmlHelper.escape_xml( item ); _buf << '</li>
##   ';  end 
##    _buf << '</ul>
##   ';
##   _buf.to_s
##   --- result ---
##    <ul>
##      <li><aaa>
##          &lt;aaa&gt;</li>
##      <li>b&b
##          b&amp;b</li>
##      <li>"ccc"
##          &quot;ccc&quot;</li>
##    </ul>
##


module Erubis
  VERSION = ('$Release: 2.7.0 $' =~ /([.\d]+)/) && $1
end

require 'erubis/engine'
#require 'erubis/generator'
#require 'erubis/converter'
#require 'erubis/evaluator'
#require 'erubis/error'
#require 'erubis/context'
#requier 'erubis/util'
require 'erubis/helper'
require 'erubis/enhancer'
#require 'erubis/tiny'
require 'erubis/engine/eruby'
#require 'erubis/engine/enhanced'    # enhanced eruby engines
#require 'erubis/engine/optimized'   # generates optimized ruby code
#require 'erubis/engine/ephp'
#require 'erubis/engine/ec'
#require 'erubis/engine/ejava'
#require 'erubis/engine/escheme'
#require 'erubis/engine/eperl'
#require 'erubis/engine/ejavascript'

require 'erubis/local-setting'
