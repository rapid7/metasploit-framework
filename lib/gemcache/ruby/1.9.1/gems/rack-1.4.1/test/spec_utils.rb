# -*- encoding: utf-8 -*-
require 'rack/utils'
require 'rack/mock'

describe Rack::Utils do

  # A helper method which checks
  # if certain query parameters 
  # are equal.
  def equal_query_to(query)
    parts = query.split('&')
    lambda{|other| (parts & other.split('&')) == parts }
  end

  def kcodeu
    one8 = RUBY_VERSION.to_f < 1.9
    default_kcode, $KCODE = $KCODE, 'U' if one8
    yield
  ensure
    $KCODE = default_kcode if one8
  end

  should "round trip binary data" do
    r = [218, 0].pack 'CC'
    if defined?(::Encoding)
      z = Rack::Utils.unescape(Rack::Utils.escape(r), Encoding::BINARY)
    else
      z = Rack::Utils.unescape(Rack::Utils.escape(r))
    end
    r.should.equal z
  end

  should "escape correctly" do
    Rack::Utils.escape("fo<o>bar").should.equal "fo%3Co%3Ebar"
    Rack::Utils.escape("a space").should.equal "a+space"
    Rack::Utils.escape("q1!2\"'w$5&7/z8)?\\").
      should.equal "q1%212%22%27w%245%267%2Fz8%29%3F%5C"
  end

  should "escape correctly for multibyte characters" do
    matz_name = "\xE3\x81\xBE\xE3\x81\xA4\xE3\x82\x82\xE3\x81\xA8".unpack("a*")[0] # Matsumoto
    matz_name.force_encoding("UTF-8") if matz_name.respond_to? :force_encoding
    Rack::Utils.escape(matz_name).should.equal '%E3%81%BE%E3%81%A4%E3%82%82%E3%81%A8'
    matz_name_sep = "\xE3\x81\xBE\xE3\x81\xA4 \xE3\x82\x82\xE3\x81\xA8".unpack("a*")[0] # Matsu moto
    matz_name_sep.force_encoding("UTF-8") if matz_name_sep.respond_to? :force_encoding
    Rack::Utils.escape(matz_name_sep).should.equal '%E3%81%BE%E3%81%A4+%E3%82%82%E3%81%A8'
  end

  if RUBY_VERSION[/^\d+\.\d+/] == '1.8'
    should "escape correctly for multibyte characters if $KCODE is set to 'U'" do
      kcodeu do
        matz_name = "\xE3\x81\xBE\xE3\x81\xA4\xE3\x82\x82\xE3\x81\xA8".unpack("a*")[0] # Matsumoto
        matz_name.force_encoding("UTF-8") if matz_name.respond_to? :force_encoding
        Rack::Utils.escape(matz_name).should.equal '%E3%81%BE%E3%81%A4%E3%82%82%E3%81%A8'
        matz_name_sep = "\xE3\x81\xBE\xE3\x81\xA4 \xE3\x82\x82\xE3\x81\xA8".unpack("a*")[0] # Matsu moto
        matz_name_sep.force_encoding("UTF-8") if matz_name_sep.respond_to? :force_encoding
        Rack::Utils.escape(matz_name_sep).should.equal '%E3%81%BE%E3%81%A4+%E3%82%82%E3%81%A8'
      end
    end

    should "unescape multibyte characters correctly if $KCODE is set to 'U'" do
      kcodeu do
        Rack::Utils.unescape('%E3%81%BE%E3%81%A4+%E3%82%82%E3%81%A8').should.equal(
          "\xE3\x81\xBE\xE3\x81\xA4 \xE3\x82\x82\xE3\x81\xA8".unpack("a*")[0])
      end
    end
  end

  should "escape objects that responds to to_s" do
    kcodeu do
      Rack::Utils.escape(:id).should.equal "id"
    end
  end

  if "".respond_to?(:encode)
    should "escape non-UTF8 strings" do
      Rack::Utils.escape("ø".encode("ISO-8859-1")).should.equal "%F8"
    end
  end
  
  should "not hang on escaping long strings that end in % (http://redmine.ruby-lang.org/issues/5149)" do
    lambda {
      timeout(1) do
        lambda {
          URI.decode_www_form_component "A string that causes catastrophic backtracking as it gets longer %"
        }.should.raise(ArgumentError)
      end
    }.should.not.raise(Timeout::Error)
  end

  should "escape path spaces with %20" do
    Rack::Utils.escape_path("foo bar").should.equal  "foo%20bar"
  end

  should "unescape correctly" do
    Rack::Utils.unescape("fo%3Co%3Ebar").should.equal "fo<o>bar"
    Rack::Utils.unescape("a+space").should.equal "a space"
    Rack::Utils.unescape("a%20space").should.equal "a space"
    Rack::Utils.unescape("q1%212%22%27w%245%267%2Fz8%29%3F%5C").
      should.equal "q1!2\"'w$5&7/z8)?\\"
  end

  should "parse query strings correctly" do
    Rack::Utils.parse_query("foo=bar").
      should.equal "foo" => "bar"
    Rack::Utils.parse_query("foo=\"bar\"").
      should.equal "foo" => "\"bar\""
    Rack::Utils.parse_query("foo=bar&foo=quux").
      should.equal "foo" => ["bar", "quux"]
    Rack::Utils.parse_query("foo=1&bar=2").
      should.equal "foo" => "1", "bar" => "2"
    Rack::Utils.parse_query("my+weird+field=q1%212%22%27w%245%267%2Fz8%29%3F").
      should.equal "my weird field" => "q1!2\"'w$5&7/z8)?"
    Rack::Utils.parse_query("foo%3Dbaz=bar").should.equal "foo=baz" => "bar"
  end

  should "parse nested query strings correctly" do
    Rack::Utils.parse_nested_query("foo").
      should.equal "foo" => nil
    Rack::Utils.parse_nested_query("foo=").
      should.equal "foo" => ""
    Rack::Utils.parse_nested_query("foo=bar").
      should.equal "foo" => "bar"
    Rack::Utils.parse_nested_query("foo=\"bar\"").
      should.equal "foo" => "\"bar\""

    Rack::Utils.parse_nested_query("foo=bar&foo=quux").
      should.equal "foo" => "quux"
    Rack::Utils.parse_nested_query("foo&foo=").
      should.equal "foo" => ""
    Rack::Utils.parse_nested_query("foo=1&bar=2").
      should.equal "foo" => "1", "bar" => "2"
    Rack::Utils.parse_nested_query("&foo=1&&bar=2").
      should.equal "foo" => "1", "bar" => "2"
    Rack::Utils.parse_nested_query("foo&bar=").
      should.equal "foo" => nil, "bar" => ""
    Rack::Utils.parse_nested_query("foo=bar&baz=").
      should.equal "foo" => "bar", "baz" => ""
    Rack::Utils.parse_nested_query("my+weird+field=q1%212%22%27w%245%267%2Fz8%29%3F").
      should.equal "my weird field" => "q1!2\"'w$5&7/z8)?"

    Rack::Utils.parse_nested_query("a=b&pid%3D1234=1023").
      should.equal "pid=1234" => "1023", "a" => "b"

    Rack::Utils.parse_nested_query("foo[]").
      should.equal "foo" => [nil]
    Rack::Utils.parse_nested_query("foo[]=").
      should.equal "foo" => [""]
    Rack::Utils.parse_nested_query("foo[]=bar").
      should.equal "foo" => ["bar"]

    Rack::Utils.parse_nested_query("foo[]=1&foo[]=2").
      should.equal "foo" => ["1", "2"]
    Rack::Utils.parse_nested_query("foo=bar&baz[]=1&baz[]=2&baz[]=3").
      should.equal "foo" => "bar", "baz" => ["1", "2", "3"]
    Rack::Utils.parse_nested_query("foo[]=bar&baz[]=1&baz[]=2&baz[]=3").
      should.equal "foo" => ["bar"], "baz" => ["1", "2", "3"]

    Rack::Utils.parse_nested_query("x[y][z]=1").
      should.equal "x" => {"y" => {"z" => "1"}}
    Rack::Utils.parse_nested_query("x[y][z][]=1").
      should.equal "x" => {"y" => {"z" => ["1"]}}
    Rack::Utils.parse_nested_query("x[y][z]=1&x[y][z]=2").
      should.equal "x" => {"y" => {"z" => "2"}}
    Rack::Utils.parse_nested_query("x[y][z][]=1&x[y][z][]=2").
      should.equal "x" => {"y" => {"z" => ["1", "2"]}}

    Rack::Utils.parse_nested_query("x[y][][z]=1").
      should.equal "x" => {"y" => [{"z" => "1"}]}
    Rack::Utils.parse_nested_query("x[y][][z][]=1").
      should.equal "x" => {"y" => [{"z" => ["1"]}]}
    Rack::Utils.parse_nested_query("x[y][][z]=1&x[y][][w]=2").
      should.equal "x" => {"y" => [{"z" => "1", "w" => "2"}]}

    Rack::Utils.parse_nested_query("x[y][][v][w]=1").
      should.equal "x" => {"y" => [{"v" => {"w" => "1"}}]}
    Rack::Utils.parse_nested_query("x[y][][z]=1&x[y][][v][w]=2").
      should.equal "x" => {"y" => [{"z" => "1", "v" => {"w" => "2"}}]}

    Rack::Utils.parse_nested_query("x[y][][z]=1&x[y][][z]=2").
      should.equal "x" => {"y" => [{"z" => "1"}, {"z" => "2"}]}
    Rack::Utils.parse_nested_query("x[y][][z]=1&x[y][][w]=a&x[y][][z]=2&x[y][][w]=3").
      should.equal "x" => {"y" => [{"z" => "1", "w" => "a"}, {"z" => "2", "w" => "3"}]}

    lambda { Rack::Utils.parse_nested_query("x[y]=1&x[y]z=2") }.
      should.raise(TypeError).
      message.should.equal "expected Hash (got String) for param `y'"

    lambda { Rack::Utils.parse_nested_query("x[y]=1&x[]=1") }.
      should.raise(TypeError).
      message.should.match /expected Array \(got [^)]*\) for param `x'/

    lambda { Rack::Utils.parse_nested_query("x[y]=1&x[y][][w]=2") }.
      should.raise(TypeError).
      message.should.equal "expected Array (got String) for param `y'"
  end

  should "build query strings correctly" do
    Rack::Utils.build_query("foo" => "bar").should.be equal_query_to("foo=bar")
    Rack::Utils.build_query("foo" => ["bar", "quux"]).
      should.be equal_query_to("foo=bar&foo=quux")
    Rack::Utils.build_query("foo" => "1", "bar" => "2").
      should.be equal_query_to("foo=1&bar=2")
    Rack::Utils.build_query("my weird field" => "q1!2\"'w$5&7/z8)?").
      should.be equal_query_to("my+weird+field=q1%212%22%27w%245%267%2Fz8%29%3F")
  end

  should "build nested query strings correctly" do
    Rack::Utils.build_nested_query("foo" => nil).should.equal "foo"
    Rack::Utils.build_nested_query("foo" => "").should.equal "foo="
    Rack::Utils.build_nested_query("foo" => "bar").should.equal "foo=bar"

    Rack::Utils.build_nested_query("foo" => "1", "bar" => "2").
      should.be equal_query_to("foo=1&bar=2")
    Rack::Utils.build_nested_query("my weird field" => "q1!2\"'w$5&7/z8)?").
      should.be equal_query_to("my+weird+field=q1%212%22%27w%245%267%2Fz8%29%3F")

    Rack::Utils.build_nested_query("foo" => [nil]).
      should.equal "foo[]"
    Rack::Utils.build_nested_query("foo" => [""]).
      should.equal "foo[]="
    Rack::Utils.build_nested_query("foo" => ["bar"]).
      should.equal "foo[]=bar"

    # The ordering of the output query string is unpredictable with 1.8's
    # unordered hash. Test that build_nested_query performs the inverse
    # function of parse_nested_query.
    [{"foo" => nil, "bar" => ""},
      {"foo" => "bar", "baz" => ""},
      {"foo" => ["1", "2"]},
      {"foo" => "bar", "baz" => ["1", "2", "3"]},
      {"foo" => ["bar"], "baz" => ["1", "2", "3"]},
      {"foo" => ["1", "2"]},
      {"foo" => "bar", "baz" => ["1", "2", "3"]},
      {"x" => {"y" => {"z" => "1"}}},
      {"x" => {"y" => {"z" => ["1"]}}},
      {"x" => {"y" => {"z" => ["1", "2"]}}},
      {"x" => {"y" => [{"z" => "1"}]}},
      {"x" => {"y" => [{"z" => ["1"]}]}},
      {"x" => {"y" => [{"z" => "1", "w" => "2"}]}},
      {"x" => {"y" => [{"v" => {"w" => "1"}}]}},
      {"x" => {"y" => [{"z" => "1", "v" => {"w" => "2"}}]}},
      {"x" => {"y" => [{"z" => "1"}, {"z" => "2"}]}},
      {"x" => {"y" => [{"z" => "1", "w" => "a"}, {"z" => "2", "w" => "3"}]}}
    ].each { |params|
      qs = Rack::Utils.build_nested_query(params)
      Rack::Utils.parse_nested_query(qs).should.equal params
    }

    lambda { Rack::Utils.build_nested_query("foo=bar") }.
      should.raise(ArgumentError).
      message.should.equal "value must be a Hash"
  end

  should "parse query strings that have a non-existent value" do
    key = "post/2011/08/27/Deux-%22rat%C3%A9s%22-de-l-Universit"
    Rack::Utils.parse_query(key).should.equal Rack::Utils.unescape(key) => nil
  end

  should "build query strings without = with non-existent values" do
    key = "post/2011/08/27/Deux-%22rat%C3%A9s%22-de-l-Universit"
    key = Rack::Utils.unescape(key)
    Rack::Utils.build_query(key => nil).should.equal Rack::Utils.escape(key)
  end

  should "escape html entities [&><'\"/]" do
    Rack::Utils.escape_html("foo").should.equal "foo"
    Rack::Utils.escape_html("f&o").should.equal "f&amp;o"
    Rack::Utils.escape_html("f<o").should.equal "f&lt;o"
    Rack::Utils.escape_html("f>o").should.equal "f&gt;o"
    Rack::Utils.escape_html("f'o").should.equal "f&#x27;o"
    Rack::Utils.escape_html('f"o').should.equal "f&quot;o"
    Rack::Utils.escape_html("f/o").should.equal "f&#x2F;o"
    Rack::Utils.escape_html("<foo></foo>").should.equal "&lt;foo&gt;&lt;&#x2F;foo&gt;"
  end

  should "escape html entities even on MRI when it's bugged" do
    test_escape = lambda do
      kcodeu do
        Rack::Utils.escape_html("\300<").should.equal "\300&lt;"
      end
    end

    if RUBY_VERSION.to_f < 1.9
      test_escape.call
    else
      test_escape.should.raise(ArgumentError)
    end
  end

  if "".respond_to?(:encode)
    should "escape html entities in unicode strings" do
      # the following will cause warnings if the regex is poorly encoded:
      Rack::Utils.escape_html("☃").should.equal "☃"
    end
  end

  should "figure out which encodings are acceptable" do
    helper = lambda do |a, b|
      Rack::Request.new(Rack::MockRequest.env_for("", "HTTP_ACCEPT_ENCODING" => a))
      Rack::Utils.select_best_encoding(a, b)
    end

    helper.call(%w(), [["x", 1]]).should.equal(nil)
    helper.call(%w(identity), [["identity", 0.0]]).should.equal(nil)
    helper.call(%w(identity), [["*", 0.0]]).should.equal(nil)

    helper.call(%w(identity), [["compress", 1.0], ["gzip", 1.0]]).should.equal("identity")

    helper.call(%w(compress gzip identity), [["compress", 1.0], ["gzip", 1.0]]).should.equal("compress")
    helper.call(%w(compress gzip identity), [["compress", 0.5], ["gzip", 1.0]]).should.equal("gzip")

    helper.call(%w(foo bar identity), []).should.equal("identity")
    helper.call(%w(foo bar identity), [["*", 1.0]]).should.equal("foo")
    helper.call(%w(foo bar identity), [["*", 1.0], ["foo", 0.9]]).should.equal("bar")

    helper.call(%w(foo bar identity), [["foo", 0], ["bar", 0]]).should.equal("identity")
    helper.call(%w(foo bar baz identity), [["*", 0], ["identity", 0.1]]).should.equal("identity")
  end

  should "return the bytesize of String" do
    Rack::Utils.bytesize("FOO\xE2\x82\xAC").should.equal 6
  end

  should "return status code for integer" do
    Rack::Utils.status_code(200).should.equal 200
  end

  should "return status code for string" do
    Rack::Utils.status_code("200").should.equal 200
  end

  should "return status code for symbol" do
    Rack::Utils.status_code(:ok).should.equal 200
  end
end

describe Rack::Utils, "byte_range" do
  should "ignore missing or syntactically invalid byte ranges" do
    Rack::Utils.byte_ranges({},500).should.equal nil
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "foobar"},500).should.equal nil
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "furlongs=123-456"},500).should.equal nil
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes="},500).should.equal nil
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=-"},500).should.equal nil
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=123,456"},500).should.equal nil
    # A range of non-positive length is syntactically invalid and ignored:
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=456-123"},500).should.equal nil
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=456-455"},500).should.equal nil
  end

  should "parse simple byte ranges" do
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=123-456"},500).should.equal [(123..456)]
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=123-"},500).should.equal [(123..499)]
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=-100"},500).should.equal [(400..499)]
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=0-0"},500).should.equal [(0..0)]
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=499-499"},500).should.equal [(499..499)]
  end

  should "truncate byte ranges" do
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=123-999"},500).should.equal [(123..499)]
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=600-999"},500).should.equal []
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=-999"},500).should.equal [(0..499)]
  end

  should "ignore unsatisfiable byte ranges" do
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=500-501"},500).should.equal []
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=500-"},500).should.equal []
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=999-"},500).should.equal []
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=-0"},500).should.equal []
  end

  should "handle byte ranges of empty files" do
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=123-456"},0).should.equal []
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=0-"},0).should.equal []
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=-100"},0).should.equal []
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=0-0"},0).should.equal []
    Rack::Utils.byte_ranges({"HTTP_RANGE" => "bytes=-0"},0).should.equal []
  end
end

describe Rack::Utils::HeaderHash do
  should "retain header case" do
    h = Rack::Utils::HeaderHash.new("Content-MD5" => "d5ff4e2a0 ...")
    h['ETag'] = 'Boo!'
    h.to_hash.should.equal "Content-MD5" => "d5ff4e2a0 ...", "ETag" => 'Boo!'
  end

  should "check existence of keys case insensitively" do
    h = Rack::Utils::HeaderHash.new("Content-MD5" => "d5ff4e2a0 ...")
    h.should.include 'content-md5'
    h.should.not.include 'ETag'
  end

  should "merge case-insensitively" do
    h = Rack::Utils::HeaderHash.new("ETag" => 'HELLO', "content-length" => '123')
    merged = h.merge("Etag" => 'WORLD', 'Content-Length' => '321', "Foo" => 'BAR')
    merged.should.equal "Etag"=>'WORLD', "Content-Length"=>'321', "Foo"=>'BAR'
  end

  should "overwrite case insensitively and assume the new key's case" do
    h = Rack::Utils::HeaderHash.new("Foo-Bar" => "baz")
    h["foo-bar"] = "bizzle"
    h["FOO-BAR"].should.equal "bizzle"
    h.length.should.equal 1
    h.to_hash.should.equal "foo-bar" => "bizzle"
  end

  should "be converted to real Hash" do
    h = Rack::Utils::HeaderHash.new("foo" => "bar")
    h.to_hash.should.be.instance_of Hash
  end

  should "convert Array values to Strings when converting to Hash" do
    h = Rack::Utils::HeaderHash.new("foo" => ["bar", "baz"])
    h.to_hash.should.equal({ "foo" => "bar\nbaz" })
  end

  should "replace hashes correctly" do
    h = Rack::Utils::HeaderHash.new("Foo-Bar" => "baz")
    j = {"foo" => "bar"}
    h.replace(j)
    h["foo"].should.equal "bar"
  end

  should "be able to delete the given key case-sensitively" do
    h = Rack::Utils::HeaderHash.new("foo" => "bar")
    h.delete("foo")
    h["foo"].should.be.nil
    h["FOO"].should.be.nil
  end

  should "be able to delete the given key case-insensitively" do
    h = Rack::Utils::HeaderHash.new("foo" => "bar")
    h.delete("FOO")
    h["foo"].should.be.nil
    h["FOO"].should.be.nil
  end

  should "return the deleted value when #delete is called on an existing key" do
    h = Rack::Utils::HeaderHash.new("foo" => "bar")
    h.delete("Foo").should.equal("bar")
  end

  should "return nil when #delete is called on a non-existant key" do
    h = Rack::Utils::HeaderHash.new("foo" => "bar")
    h.delete("Hello").should.be.nil
  end

  should "avoid unnecessary object creation if possible" do
    a = Rack::Utils::HeaderHash.new("foo" => "bar")
    b = Rack::Utils::HeaderHash.new(a)
    b.object_id.should.equal(a.object_id)
    b.should.equal(a)
  end

  should "convert Array values to Strings when responding to #each" do
    h = Rack::Utils::HeaderHash.new("foo" => ["bar", "baz"])
    h.each do |k,v|
      k.should.equal("foo")
      v.should.equal("bar\nbaz")
    end
  end

  should "not create headers out of thin air" do
    h = Rack::Utils::HeaderHash.new
    h['foo']
    h['foo'].should.be.nil
    h.should.not.include 'foo'
  end
end

describe Rack::Utils::Context do
  class ContextTest
    attr_reader :app
    def initialize app; @app=app; end
    def call env; context env; end
    def context env, app=@app; app.call(env); end
  end
  test_target1 = proc{|e| e.to_s+' world' }
  test_target2 = proc{|e| e.to_i+2 }
  test_target3 = proc{|e| nil }
  test_target4 = proc{|e| [200,{'Content-Type'=>'text/plain', 'Content-Length'=>'0'},['']] }
  test_app = ContextTest.new test_target4

  should "set context correctly" do
    test_app.app.should.equal test_target4
    c1 = Rack::Utils::Context.new(test_app, test_target1)
    c1.for.should.equal test_app
    c1.app.should.equal test_target1
    c2 = Rack::Utils::Context.new(test_app, test_target2)
    c2.for.should.equal test_app
    c2.app.should.equal test_target2
  end

  should "alter app on recontexting" do
    c1 = Rack::Utils::Context.new(test_app, test_target1)
    c2 = c1.recontext(test_target2)
    c2.for.should.equal test_app
    c2.app.should.equal test_target2
    c3 = c2.recontext(test_target3)
    c3.for.should.equal test_app
    c3.app.should.equal test_target3
  end

  should "run different apps" do
    c1 = Rack::Utils::Context.new test_app, test_target1
    c2 = c1.recontext test_target2
    c3 = c2.recontext test_target3
    c4 = c3.recontext test_target4
    a4 = Rack::Lint.new c4
    a5 = Rack::Lint.new test_app
    r1 = c1.call('hello')
    r1.should.equal 'hello world'
    r2 = c2.call(2)
    r2.should.equal 4
    r3 = c3.call(:misc_symbol)
    r3.should.be.nil
    r4 = Rack::MockRequest.new(a4).get('/')
    r4.status.should.equal 200
    r5 = Rack::MockRequest.new(a5).get('/')
    r5.status.should.equal 200
    r4.body.should.equal r5.body
  end
end
