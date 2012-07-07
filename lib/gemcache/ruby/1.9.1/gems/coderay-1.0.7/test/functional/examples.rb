require 'test/unit'

$:.unshift File.expand_path('../../../lib', __FILE__)
require 'coderay'

class ExamplesTest < Test::Unit::TestCase
  
  def test_examples
    # output as HTML div (using inline CSS styles)
    div = CodeRay.scan('puts "Hello, world!"', :ruby).div
    assert_equal <<-DIV, div
<div class="CodeRay">
  <div class="code"><pre>puts <span style="background-color:hsla(0,100%,50%,0.05)"><span style="color:#710">&quot;</span><span style="color:#D20">Hello, world!</span><span style="color:#710">&quot;</span></span></pre></div>
</div>
    DIV
    
    # ...with line numbers
    div = CodeRay.scan(<<-CODE.chomp, :ruby).div(:line_numbers => :table)
5.times do
  puts 'Hello, world!'
end
    CODE
    assert_equal <<-DIV, div
<table class="CodeRay"><tr>
  <td class="line-numbers" title="double click to toggle" ondblclick="with (this.firstChild.style) { display = (display == '') ? 'none' : '' }"><pre><a href="#n1" name="n1">1</a>
<a href="#n2" name="n2">2</a>
<a href="#n3" name="n3">3</a>
</pre></td>
  <td class="code"><pre><span style="color:#00D">5</span>.times <span style="color:#080;font-weight:bold">do</span>
  puts <span style="background-color:hsla(0,100%,50%,0.05)"><span style="color:#710">'</span><span style="color:#D20">Hello, world!</span><span style="color:#710">'</span></span>
<span style="color:#080;font-weight:bold">end</span></pre></td>
</tr></table>
    DIV
    
    # output as standalone HTML page (using CSS classes)
    page = CodeRay.scan('puts "Hello, world!"', :ruby).page
    assert_match <<-PAGE, page
<body>

<table class="CodeRay"><tr>
  <td class="line-numbers" title="double click to toggle" ondblclick="with (this.firstChild.style) { display = (display == '') ? 'none' : '' }"><pre>
</pre></td>
  <td class="code"><pre>puts <span class="string"><span class="delimiter">&quot;</span><span class="content">Hello, world!</span><span class="delimiter">&quot;</span></span></pre></td>
</tr></table>

</body>
    PAGE
    
    # keep scanned tokens for later use
    tokens = CodeRay.scan('{ "just": "an", "example": 42 }', :json)
    assert_kind_of CodeRay::TokensProxy, tokens
    
    assert_equal ["{", :operator, " ", :space, :begin_group, :key,
      "\"", :delimiter, "just", :content, "\"", :delimiter,
      :end_group, :key, ":", :operator, " ", :space,
      :begin_group, :string, "\"", :delimiter, "an", :content,
      "\"", :delimiter, :end_group, :string, ",", :operator,
      " ", :space, :begin_group, :key, "\"", :delimiter,
      "example", :content, "\"", :delimiter, :end_group, :key,
      ":", :operator, " ", :space, "42", :integer,
      " ", :space, "}", :operator], tokens.tokens
    
    # produce a token statistic
    assert_equal <<-STATISTIC, tokens.statistic

Code Statistics

Tokens                  26
  Non-Whitespace        15
Bytes Total             31

Token Types (7):
  type                     count     ratio    size (average)
-------------------------------------------------------------
  TOTAL                       26  100.00 %     1.2
  delimiter                    6   23.08 %     1.0
  operator                     5   19.23 %     1.0
  space                        5   19.23 %     1.0
  key                          4   15.38 %     0.0
  :begin_group                 3   11.54 %     0.0
  :end_group                   3   11.54 %     0.0
  content                      3   11.54 %     4.3
  string                       2    7.69 %     0.0
  integer                      1    3.85 %     2.0

    STATISTIC
    
    # count the tokens
    assert_equal 26, tokens.count
    
    # produce a HTML div, but with CSS classes
    div = tokens.div(:css => :class)
    assert_equal <<-DIV, div
<div class="CodeRay">
  <div class="code"><pre>{ <span class="key"><span class="delimiter">&quot;</span><span class="content">just</span><span class="delimiter">&quot;</span></span>: <span class="string"><span class="delimiter">&quot;</span><span class="content">an</span><span class="delimiter">&quot;</span></span>, <span class="key"><span class="delimiter">&quot;</span><span class="content">example</span><span class="delimiter">&quot;</span></span>: <span class="integer">42</span> }</pre></div>
</div>
    DIV
    
    # highlight a file (HTML div); guess the file type base on the extension
    assert_equal :ruby, CodeRay::FileType[__FILE__]
    
    # get a new scanner for Python
    python_scanner = CodeRay.scanner :python
    assert_kind_of CodeRay::Scanners::Python, python_scanner
    
    # get a new encoder for terminal
    terminal_encoder = CodeRay.encoder :term
    assert_kind_of CodeRay::Encoders::Terminal, terminal_encoder
    
    # scanning into tokens
    tokens = python_scanner.tokenize 'import this;  # The Zen of Python'
    assert_equal ["import", :keyword, " ", :space, "this", :include,
      ";", :operator, "  ", :space, "# The Zen of Python", :comment], tokens
    
    # format the tokens
    term = terminal_encoder.encode_tokens(tokens)
    assert_equal "\e[1;31mimport\e[0m \e[33mthis\e[0m;  \e[37m# The Zen of Python\e[0m", term
    
    # re-using scanner and encoder
    ruby_highlighter = CodeRay::Duo[:ruby, :div]
    div = ruby_highlighter.encode('puts "Hello, world!"')
    assert_equal <<-DIV, div
<div class="CodeRay">
  <div class="code"><pre>puts <span style="background-color:hsla(0,100%,50%,0.05)"><span style="color:#710">&quot;</span><span style="color:#D20">Hello, world!</span><span style="color:#710">&quot;</span></span></pre></div>
</div>
    DIV
  end
  
end
