if ENV['RAILS_ROOT']
  environment = File.expand_path('vendor/gems/environment', ENV['RAILS_ROOT'])
  require environment if File.exist?("#{environment}.rb")
end

$:.unshift File.expand_path('../../lib', __FILE__)

require 'test/unit'
require 'action_view'
require 'action_controller'
require 'active_model'
require 'prototype_helper'

class Bunny < Struct.new(:Bunny, :id)
end

class Author
  extend ActiveModel::Naming

  attr_reader :id
  def save; @id = 1 end
  def new_record?; @id.nil? end
  def name
    @id.nil? ? 'new author' : "author ##{@id}"
  end
end

class Article
  extend ActiveModel::Naming

  attr_reader :id
  attr_reader :author_id
  def save; @id = 1; @author_id = 1 end
  def new_record?; @id.nil? end
  def name
    @id.nil? ? 'new article' : "article ##{@id}"
  end
end

class Author::Nested < Author; end

class PrototypeHelperTest < ActionView::TestCase
  attr_accessor :formats, :output_buffer, :template_format

  def _evaluate_assigns_and_ivars() end

  def reset_formats(format)
    @format = format
  end

  def setup
    @record = @author = Author.new
    @article = Article.new
    super
    @template = self
    @controller = Class.new do
      def url_for(options)
        if options.is_a?(String)
          options
        else
          url =  "http://www.example.com/"
          url << options[:action].to_s if options and options[:action]
          url << "?a=#{options[:a]}" if options && options[:a]
          url << "&b=#{options[:b]}" if options && options[:a] && options[:b]
          url
        end
      end
    end.new
  end


  def test_observe_form
    assert_dom_equal %(<script type=\"text/javascript\">\n//<![CDATA[\nnew Form.Observer('cart', 2, function(element, value) {new Ajax.Request('http://www.example.com/cart_changed', {asynchronous:true, evalScripts:true, parameters:value})})\n//]]>\n</script>),
      observe_form("cart", :frequency => 2, :url => { :action => "cart_changed" })
  end

  def test_observe_form_using_function_for_callback
    assert_dom_equal %(<script type=\"text/javascript\">\n//<![CDATA[\nnew Form.Observer('cart', 2, function(element, value) {alert('Form changed')})\n//]]>\n</script>),
      observe_form("cart", :frequency => 2, :function => "alert('Form changed')")
  end

  def test_observe_field
    assert_dom_equal %(<script type=\"text/javascript\">\n//<![CDATA[\nnew Form.Element.Observer('glass', 300, function(element, value) {new Ajax.Request('http://www.example.com/reorder_if_empty', {asynchronous:true, evalScripts:true, parameters:value})})\n//]]>\n</script>),
      observe_field("glass", :frequency => 5.minutes, :url => { :action => "reorder_if_empty" })
  end

  def test_observe_field_using_with_option
    expected = %(<script type=\"text/javascript\">\n//<![CDATA[\nnew Form.Element.Observer('glass', 300, function(element, value) {new Ajax.Request('http://www.example.com/check_value', {asynchronous:true, evalScripts:true, parameters:'id=' + encodeURIComponent(value)})})\n//]]>\n</script>)
    assert_dom_equal expected, observe_field("glass", :frequency => 5.minutes, :url => { :action => "check_value" }, :with => 'id')
    assert_dom_equal expected, observe_field("glass", :frequency => 5.minutes, :url => { :action => "check_value" }, :with => "'id=' + encodeURIComponent(value)")
  end

  def test_observe_field_using_json_in_with_option
    expected = %(<script type=\"text/javascript\">\n//<![CDATA[\nnew Form.Element.Observer('glass', 300, function(element, value) {new Ajax.Request('http://www.example.com/check_value', {asynchronous:true, evalScripts:true, parameters:{'id':value}})})\n//]]>\n</script>)
    assert_dom_equal expected, observe_field("glass", :frequency => 5.minutes, :url => { :action => "check_value" }, :with => "{'id':value}")
  end

  def test_observe_field_using_function_for_callback
    assert_dom_equal %(<script type=\"text/javascript\">\n//<![CDATA[\nnew Form.Element.Observer('glass', 300, function(element, value) {alert('Element changed')})\n//]]>\n</script>),
      observe_field("glass", :frequency => 5.minutes, :function => "alert('Element changed')")
  end

  def test_observe_field_without_frequency
    assert_dom_equal %(<script type=\"text/javascript\">\n//<![CDATA[\nnew Form.Element.EventObserver('glass', function(element, value) {new Ajax.Request('http://www.example.com/', {asynchronous:true, evalScripts:true, parameters:value})})\n//]]>\n</script>),
      observe_field("glass")
  end


  def test_periodically_call_remote
    assert_dom_equal %(<script type="text/javascript">\n//<![CDATA[\nnew PeriodicalExecuter(function() {new Ajax.Updater('schremser_bier', 'http://www.example.com/mehr_bier', {asynchronous:true, evalScripts:true})}, 10)\n//]]>\n</script>),
      periodically_call_remote(:update => "schremser_bier", :url => { :action => "mehr_bier" })
  end

  def test_periodically_call_remote_with_frequency
    assert_dom_equal(
      "<script type=\"text/javascript\">\n//<![CDATA[\nnew PeriodicalExecuter(function() {new Ajax.Request('http://www.example.com/', {asynchronous:true, evalScripts:true})}, 2)\n//]]>\n</script>",
      periodically_call_remote(:frequency => 2)
    )
  end


  def test_form_remote_tag
    assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater('glass_of_beer', 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this)}); return false;\">),
      form_remote_tag(:update => "glass_of_beer", :url => { :action => :fast  })
    assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater({success:'glass_of_beer'}, 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this)}); return false;\">),
      form_remote_tag(:update => { :success => "glass_of_beer" }, :url => { :action => :fast  })
    assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater({failure:'glass_of_water'}, 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this)}); return false;\">),
      form_remote_tag(:update => { :failure => "glass_of_water" }, :url => { :action => :fast  })
    assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater({success:'glass_of_beer',failure:'glass_of_water'}, 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this)}); return false;\">),
      form_remote_tag(:update => { :success => 'glass_of_beer', :failure => "glass_of_water" }, :url => { :action => :fast  })
  end

  def test_form_remote_tag_with_method
    assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater('glass_of_beer', 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this)}); return false;\"><div style='margin:0;padding:0;display:inline'><input name='_method' type='hidden' value='put' /></div>),
      form_remote_tag(:update => "glass_of_beer", :url => { :action => :fast  }, :html => { :method => :put })
  end

  def test_form_remote_tag_with_block_in_erb
    __in_erb_template = ''
    form_remote_tag(:update => "glass_of_beer", :url => { :action => :fast  }) { concat "Hello world!" }
    assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater('glass_of_beer', 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this)}); return false;\">Hello world!</form>), output_buffer
  end

  def test_on_callbacks
    callbacks = [:uninitialized, :loading, :loaded, :interactive, :complete, :success, :failure]
    callbacks.each do |callback|
      assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater('glass_of_beer', 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, on#{callback.to_s.capitalize}:function(request){monkeys();}, parameters:Form.serialize(this)}); return false;">),
        form_remote_tag(:update => "glass_of_beer", :url => { :action => :fast  }, callback=>"monkeys();")
      assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater({success:'glass_of_beer'}, 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, on#{callback.to_s.capitalize}:function(request){monkeys();}, parameters:Form.serialize(this)}); return false;">),
        form_remote_tag(:update => { :success => "glass_of_beer" }, :url => { :action => :fast  }, callback=>"monkeys();")
      assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater({failure:'glass_of_beer'}, 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, on#{callback.to_s.capitalize}:function(request){monkeys();}, parameters:Form.serialize(this)}); return false;">),
        form_remote_tag(:update => { :failure => "glass_of_beer" }, :url => { :action => :fast  }, callback=>"monkeys();")
      assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater({success:'glass_of_beer',failure:'glass_of_water'}, 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, on#{callback.to_s.capitalize}:function(request){monkeys();}, parameters:Form.serialize(this)}); return false;">),
        form_remote_tag(:update => { :success => "glass_of_beer", :failure => "glass_of_water" }, :url => { :action => :fast  }, callback=>"monkeys();")
    end

    #HTTP status codes 200 up to 599 have callbacks
    #these should work
    100.upto(599) do |callback|
      assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater('glass_of_beer', 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, on#{callback.to_s.capitalize}:function(request){monkeys();}, parameters:Form.serialize(this)}); return false;">),
        form_remote_tag(:update => "glass_of_beer", :url => { :action => :fast  }, callback=>"monkeys();")
    end

    #test 200 and 404
    assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater('glass_of_beer', 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, on200:function(request){monkeys();}, on404:function(request){bananas();}, parameters:Form.serialize(this)}); return false;">),
      form_remote_tag(:update => "glass_of_beer", :url => { :action => :fast  }, 200=>"monkeys();", 404=>"bananas();")

    #these shouldn't
    1.upto(99) do |callback|
      assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater('glass_of_beer', 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this)}); return false;">),
        form_remote_tag(:update => "glass_of_beer", :url => { :action => :fast  }, callback=>"monkeys();")
    end
    600.upto(999) do |callback|
      assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater('glass_of_beer', 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this)}); return false;">),
        form_remote_tag(:update => "glass_of_beer", :url => { :action => :fast  }, callback=>"monkeys();")
    end

    #test ultimate combo
    assert_dom_equal %(<form action=\"http://www.example.com/fast\" method=\"post\" onsubmit=\"new Ajax.Updater('glass_of_beer', 'http://www.example.com/fast', {asynchronous:true, evalScripts:true, on200:function(request){monkeys();}, on404:function(request){bananas();}, onComplete:function(request){c();}, onFailure:function(request){f();}, onLoading:function(request){c1()}, onSuccess:function(request){s()}, parameters:Form.serialize(this)}); return false;\">),
      form_remote_tag(:update => "glass_of_beer", :url => { :action => :fast  }, :loading => "c1()", :success => "s()", :failure => "f();", :complete => "c();", 200=>"monkeys();", 404=>"bananas();")
  end

  def test_remote_form_for_with_record_identification_with_new_record
    remote_form_for(@record, {:html => { :id => 'create-author' }}) {}

    expected = %(<form action='#{authors_path}' onsubmit="new Ajax.Request('#{authors_path}', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this)}); return false;" class='new_author' id='create-author' method='post'></form>)
    assert_dom_equal expected, output_buffer
  end

  def test_remote_form_for_with_record_identification_without_html_options
    remote_form_for(@record) {}

    expected = %(<form action='#{authors_path}' onsubmit="new Ajax.Request('#{authors_path}', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this)}); return false;" class='new_author' method='post' id='new_author'></form>)
    assert_dom_equal expected, output_buffer
  end

  def test_remote_form_for_with_record_identification_with_existing_record
    @record.save
    remote_form_for(@record) {}

    expected = %(<form action='#{author_path(@record)}' id='edit_author_1' method='post' onsubmit="new Ajax.Request('#{author_path(@record)}', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this)}); return false;" class='edit_author'><div style='margin:0;padding:0;display:inline'><input name='_method' type='hidden' value='put' /></div></form>)
    assert_dom_equal expected, output_buffer
  end

  def test_remote_form_for_with_new_object_in_list
    remote_form_for([@author, @article]) {}

    expected = %(<form action='#{author_articles_path(@author)}' onsubmit="new Ajax.Request('#{author_articles_path(@author)}', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this)}); return false;" class='new_article' method='post' id='new_article'></form>)
    assert_dom_equal expected, output_buffer
  end

  def test_remote_form_for_with_existing_object_in_list
    @author.save
    @article.save
    remote_form_for([@author, @article]) {}

    expected = %(<form action='#{author_article_path(@author, @article)}' id='edit_article_1' method='post' onsubmit="new Ajax.Request('#{author_article_path(@author, @article)}', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this)}); return false;" class='edit_article'><div style='margin:0;padding:0;display:inline'><input name='_method' type='hidden' value='put' /></div></form>)
    assert_dom_equal expected, output_buffer
  end


  def test_button_to_remote
    assert_dom_equal %(<input class=\"fine\" type=\"button\" value=\"Remote outpost\" onclick=\"new Ajax.Request('http://www.example.com/whatnot', {asynchronous:true, evalScripts:true});\" />),
      button_to_remote("Remote outpost", { :url => { :action => "whatnot"  }}, { :class => "fine"  })
    assert_dom_equal %(<input type=\"button\" value=\"Remote outpost\" onclick=\"new Ajax.Request('http://www.example.com/whatnot', {asynchronous:true, evalScripts:true, onComplete:function(request){alert(request.reponseText)}});\" />),
      button_to_remote("Remote outpost", :complete => "alert(request.reponseText)", :url => { :action => "whatnot"  })
    assert_dom_equal %(<input type=\"button\" value=\"Remote outpost\" onclick=\"new Ajax.Request('http://www.example.com/whatnot', {asynchronous:true, evalScripts:true, onSuccess:function(request){alert(request.reponseText)}});\" />),
      button_to_remote("Remote outpost", :success => "alert(request.reponseText)", :url => { :action => "whatnot"  })
    assert_dom_equal %(<input type=\"button\" value=\"Remote outpost\" onclick=\"new Ajax.Request('http://www.example.com/whatnot', {asynchronous:true, evalScripts:true, onFailure:function(request){alert(request.reponseText)}});\" />),
      button_to_remote("Remote outpost", :failure => "alert(request.reponseText)", :url => { :action => "whatnot"  })
    assert_dom_equal %(<input type=\"button\" value=\"Remote outpost\" onclick=\"new Ajax.Request('http://www.example.com/whatnot?a=10&amp;b=20', {asynchronous:true, evalScripts:true, onFailure:function(request){alert(request.reponseText)}});\" />),
      button_to_remote("Remote outpost", :failure => "alert(request.reponseText)", :url => { :action => "whatnot", :a => '10', :b => '20' })
  end

  def test_submit_to_remote
    assert_dom_equal %(<input name=\"More beer!\" onclick=\"new Ajax.Updater('empty_bottle', 'http://www.example.com/', {asynchronous:true, evalScripts:true, parameters:Form.serialize(this.form)});\" type=\"button\" value=\"1000000\" />),
      submit_to_remote("More beer!", 1_000_000, :update => "empty_bottle")
  end


  def test_link_to_remote
    assert_dom_equal %(<a class=\"fine\" href=\"#\" onclick=\"new Ajax.Request('http://www.example.com/whatnot', {asynchronous:true, evalScripts:true}); return false;\">Remote outauthor</a>),
      link_to_remote("Remote outauthor", { :url => { :action => "whatnot"  }}, { :class => "fine"  })
    assert_dom_equal %(<a href=\"#\" onclick=\"new Ajax.Request('http://www.example.com/whatnot', {asynchronous:true, evalScripts:true, onComplete:function(request){alert(request.responseText)}}); return false;\">Remote outauthor</a>),
      link_to_remote("Remote outauthor", :complete => "alert(request.responseText)", :url => { :action => "whatnot"  })
    assert_dom_equal %(<a href=\"#\" onclick=\"new Ajax.Request('http://www.example.com/whatnot', {asynchronous:true, evalScripts:true, onSuccess:function(request){alert(request.responseText)}}); return false;\">Remote outauthor</a>),
      link_to_remote("Remote outauthor", :success => "alert(request.responseText)", :url => { :action => "whatnot"  })
    assert_dom_equal %(<a href=\"#\" onclick=\"new Ajax.Request('http://www.example.com/whatnot', {asynchronous:true, evalScripts:true, onFailure:function(request){alert(request.responseText)}}); return false;\">Remote outauthor</a>),
      link_to_remote("Remote outauthor", :failure => "alert(request.responseText)", :url => { :action => "whatnot"  })
    assert_dom_equal %(<a href=\"#\" onclick=\"new Ajax.Request('http://www.example.com/whatnot?a=10&amp;b=20', {asynchronous:true, evalScripts:true, onFailure:function(request){alert(request.responseText)}}); return false;\">Remote outauthor</a>),
      link_to_remote("Remote outauthor", :failure => "alert(request.responseText)", :url => { :action => "whatnot", :a => '10', :b => '20' })
    assert_dom_equal %(<a href=\"#\" onclick=\"new Ajax.Request('http://www.example.com/whatnot', {asynchronous:false, evalScripts:true}); return false;\">Remote outauthor</a>),
      link_to_remote("Remote outauthor", :url => { :action => "whatnot" }, :type => :synchronous)
    assert_dom_equal %(<a href=\"#\" onclick=\"new Ajax.Request('http://www.example.com/whatnot', {asynchronous:true, evalScripts:true, insertion:'bottom'}); return false;\">Remote outauthor</a>),
      link_to_remote("Remote outauthor", :url => { :action => "whatnot" }, :position => :bottom)
  end

  def test_link_to_remote_html_options
    assert_dom_equal %(<a class=\"fine\" href=\"#\" onclick=\"new Ajax.Request('http://www.example.com/whatnot', {asynchronous:true, evalScripts:true}); return false;\">Remote outauthor</a>),
      link_to_remote("Remote outauthor", { :url => { :action => "whatnot"  }, :html => { :class => "fine" } })
  end

  def test_link_to_remote_url_quote_escaping
    assert_dom_equal %(<a href="#" onclick="new Ajax.Request('http://www.example.com/whatnot\\\'s', {asynchronous:true, evalScripts:true}); return false;">Remote</a>),
      link_to_remote("Remote", { :url => { :action => "whatnot's" } })
  end

  protected
    def request_forgery_protection_token
      nil
    end

    def protect_against_forgery?
      false
    end

    def create_generator
      block = Proc.new { |*args| yield *args if block_given? }
      JavaScriptGenerator.new self, &block
    end

    def author_path(record)
      "/authors/#{record.id}"
    end

    def authors_path
      "/authors"
    end

    def author_articles_path(author)
      "/authors/#{author.id}/articles"
    end

    def author_article_path(author, article)
      "/authors/#{author.id}/articles/#{article.id}"
    end
end
