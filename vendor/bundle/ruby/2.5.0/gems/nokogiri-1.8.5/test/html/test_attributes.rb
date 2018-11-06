require "helper"

module Nokogiri
  module HTML
    class TestAttr < Nokogiri::TestCase
      unless Nokogiri::VersionInfo.instance.libxml2? && Nokogiri::VersionInfo.instance.libxml2_using_system?
        #
        #  libxml2 >= 2.9.2 fails to escape comments within some attributes. It
        #  wants to ensure these comments can be treated as "server-side includes",
        #  but as a result fails to ensure that serialization is well-formed,
        #  resulting in an opportunity for XSS injection of code into a final
        #  re-parsed document (presumably in a browser).
        #
        #  the offending commit is:
        #
        #    https://github.com/GNOME/libxml2/commit/960f0e2
        #
        #  we'll test this by parsing the HTML, serializing it, then
        #  re-parsing it to ensure there isn't any ambiguity in the output
        #  that might allow code injection into a browser consuming
        #  "sanitized" output.
        #
        #  complaints have been made upstream about this behavior, notably at
        #
        #    https://bugzilla.gnome.org/show_bug.cgi?id=769760
        #
        #  and multiple CVEs have been declared and fixed in downstream
        #  libraries as a result, a list is being kept up to date here:
        #
        #    https://github.com/flavorjones/loofah/issues/144
        #
        [
          #
          #  these tags and attributes are determined by the code at:
          #
          #    https://git.gnome.org/browse/libxml2/tree/HTMLtree.c?h=v2.9.2#n714
          #
          {tag: "a",   attr: "href"},
          {tag: "div", attr: "href"},
          {tag: "a",   attr: "action"},
          {tag: "div", attr: "action"},
          {tag: "a",   attr: "src"},
          {tag: "div", attr: "src"},
          {tag: "a",   attr: "name"},
          #
          #  note that div+name is _not_ affected by the libxml2 issue.
          #  but we test it anyway to ensure our logic isn't modifying
          #  attributes that don't need modifying.
          #
          {tag: "div", attr: "name", unescaped: true},
        ].each do |config|

          define_method "test_uri_escaping_of_#{config[:attr]}_attr_in_#{config[:tag]}_tag" do
            html = %{<#{config[:tag]} #{config[:attr]}='examp<!--" unsafeattr=unsafevalue()>-->le.com'>test</#{config[:tag]}>}

            reparsed = HTML.fragment(HTML.fragment(html).to_html)
            attributes = reparsed.at_css(config[:tag]).attribute_nodes

            assert_equal [config[:attr]], attributes.collect(&:name)
            if Nokogiri::VersionInfo.instance.libxml2?
              if config[:unescaped]
                #
                #  this attribute was emitted wrapped in single-quotes, so a double quote is A-OK.
                #  assert that this attribute's serialization is unaffected.
                #
                assert_equal %{examp<!--" unsafeattr=unsafevalue()>-->le.com}, attributes.first.value
              else
                #
                #  let's match the behavior in libxml < 2.9.2.
                #  test that this attribute's serialization is well-formed and sanitized.
                #
                assert_equal %{examp<!--%22%20unsafeattr=unsafevalue()>-->le.com}, attributes.first.value
              end
            else
              #
              #  yay for consistency in javaland. move along, nothing to see here.
              #
              assert_equal %{examp<!--%22 unsafeattr=unsafevalue()>-->le.com}, attributes.first.value
            end
          end
        end
      end
    end
  end
end
