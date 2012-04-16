require 'test/unit'
require File.expand_path('../../lib/assert_warning', __FILE__)

$:.unshift File.expand_path('../../../lib', __FILE__)
require 'coderay'

begin
  require 'rubygems' unless defined? Gem
  gem 'RedCloth', '>= 4.0.3' rescue nil
  require 'redcloth'
rescue LoadError
  warn 'RedCloth not found - skipping for_redcloth tests.'
  undef RedCloth if defined? RedCloth
end

class BasicTest < Test::Unit::TestCase
  
  def test_for_redcloth
    require 'coderay/for_redcloth'
    assert_equal "<p><span lang=\"ruby\" class=\"CodeRay\">puts <span style=\"background-color:hsla(0,100%,50%,0.05)\"><span style=\"color:#710\">&quot;</span><span style=\"color:#D20\">Hello, World!</span><span style=\"color:#710\">&quot;</span></span></span></p>",
      RedCloth.new('@[ruby]puts "Hello, World!"@').to_html
    assert_equal <<-BLOCKCODE.chomp,
<div lang="ruby" class="CodeRay">
  <div class="code"><pre>puts <span style="background-color:hsla(0,100%,50%,0.05)"><span style="color:#710">&quot;</span><span style="color:#D20">Hello, World!</span><span style="color:#710">&quot;</span></span></pre></div>
</div>
      BLOCKCODE
      RedCloth.new('bc[ruby]. puts "Hello, World!"').to_html
  end
  
  def test_for_redcloth_no_lang
    require 'coderay/for_redcloth'
    assert_equal "<p><code>puts \"Hello, World!\"</code></p>",
      RedCloth.new('@puts "Hello, World!"@').to_html
    assert_equal <<-BLOCKCODE.chomp,
<pre><code>puts \"Hello, World!\"</code></pre>
      BLOCKCODE
      RedCloth.new('bc. puts "Hello, World!"').to_html
  end
  
  def test_for_redcloth_style
    require 'coderay/for_redcloth'
    assert_equal <<-BLOCKCODE.chomp,
<pre style=\"color: red;\"><code style=\"color: red;\">puts \"Hello, World!\"</code></pre>
      BLOCKCODE
      RedCloth.new('bc{color: red}. puts "Hello, World!"').to_html
  end
  
  def test_for_redcloth_escapes
    require 'coderay/for_redcloth'
    assert_equal '<p><span lang="ruby" class="CodeRay">&gt;</span></p>',
      RedCloth.new('@[ruby]>@').to_html
    assert_equal <<-BLOCKCODE.chomp,
<div lang="ruby" class="CodeRay">
  <div class="code"><pre>&amp;</pre></div>
</div>
      BLOCKCODE
      RedCloth.new('bc[ruby]. &').to_html
  end
  
  def test_for_redcloth_escapes2
    require 'coderay/for_redcloth'
    assert_equal "<p><span lang=\"c\" class=\"CodeRay\"><span style=\"color:#579\">#include</span> <span style=\"color:#B44;font-weight:bold\">&lt;test.h&gt;</span></span></p>",
      RedCloth.new('@[c]#include <test.h>@').to_html
  end
  
  # See http://jgarber.lighthouseapp.com/projects/13054/tickets/124-code-markup-does-not-allow-brackets.
  def test_for_redcloth_false_positive
    require 'coderay/for_redcloth'
    assert_warning 'CodeRay::Scanners could not load plugin :project; falling back to :text' do
      assert_equal '<p><code>[project]_dff.skjd</code></p>',
        RedCloth.new('@[project]_dff.skjd@').to_html
    end
    # false positive, but expected behavior / known issue
    assert_equal "<p><span lang=\"ruby\" class=\"CodeRay\">_dff.skjd</span></p>",
      RedCloth.new('@[ruby]_dff.skjd@').to_html
    assert_warning 'CodeRay::Scanners could not load plugin :project; falling back to :text' do
      assert_equal <<-BLOCKCODE.chomp,
<pre><code>[project]_dff.skjd</code></pre>
        BLOCKCODE
        RedCloth.new('bc. [project]_dff.skjd').to_html
    end
  end
  
end if defined? RedCloth