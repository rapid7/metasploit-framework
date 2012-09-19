require "helper"

class TestXsltTransforms < Nokogiri::TestCase
  def setup
    @doc = Nokogiri::XML(File.open(XML_FILE))
  end

  def test_class_methods
    style = Nokogiri::XSLT(File.read(XSLT_FILE))

    assert result = style.apply_to(@doc, ['title', '"Grandma"'])
    assert_match %r{<h1>Grandma</h1>}, result
  end

  def test_transform
    assert style = Nokogiri::XSLT.parse(File.read(XSLT_FILE))

    assert result = style.apply_to(@doc, ['title', '"Booyah"'])
    assert_match %r{<h1>Booyah</h1>}, result
    assert_match %r{<th.*Employee ID</th>}, result
    assert_match %r{<th.*Name</th>}, result
    assert_match %r{<th.*Position</th>}, result
    assert_match %r{<th.*Salary</th>}, result
    assert_match %r{<td>EMP0003</td>}, result
    assert_match %r{<td>Margaret Martin</td>}, result
    assert_match %r{<td>Computer Specialist</td>}, result
    assert_match %r{<td>100,000</td>}, result
    assert_no_match %r{Dallas|Texas}, result
    assert_no_match %r{Female}, result

    assert result = style.apply_to(@doc, ['title', '"Grandma"'])
    assert_match %r{<h1>Grandma</h1>}, result

    assert result = style.apply_to(@doc)
    assert_match %r{<h1></h1>}, result
  end

  def test_transform_with_output_style
    xslt = ""
    if Nokogiri.jruby?
      xslt = Nokogiri::XSLT(<<-eoxslt)
<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text" version="1.0"
encoding="iso-8859-1" indent="yes"/>

<xsl:param name="title"/>

<xsl:template match="/">
  <html>
  <body>
    <xsl:for-each select="staff/employee">
    <tr>
      <td><xsl:value-of select="employeeId"/></td>
      <td><xsl:value-of select="name"/></td>
      <td><xsl:value-of select="position"/></td>
      <td><xsl:value-of select="salary"/></td>
    </tr>
    </xsl:for-each>
  </body>
  </html>
</xsl:template>

</xsl:stylesheet>
      eoxslt
    else
      xslt = Nokogiri::XSLT(<<-eoxslt)
<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text" version="1.0"
encoding="iso-8859-1" indent="yes"/>

<xsl:param name="title"/>

<xsl:template match="/">
  <html>
  <body>
    <xsl:for-each select="staff/employee">
    <tr>
      <td><xsl:value-of select="employeeId"/></td>
      <td><xsl:value-of select="name"/></td>
      <td><xsl:value-of select="position"/></td>
      <td><xsl:value-of select="salary"/></td>
    </tr>
    </xsl:for-each>
    </table>
  </body>
  </html>
</xsl:template>

</xsl:stylesheet>
      eoxslt
    end
    assert_no_match(/<td>/, xslt.apply_to(@doc, ['title', 'foo']))
  end

  def test_transform_arg_error
    assert style = Nokogiri::XSLT(File.read(XSLT_FILE))
    assert_raises(TypeError) do
      style.transform(@doc, :foo)
    end
  end

  def test_transform_with_hash
    assert style = Nokogiri::XSLT(File.read(XSLT_FILE))
    result = style.transform(@doc, {'title' => '"Booyah"'})
    assert result.html?
    assert_equal "Booyah", result.at_css("h1").content
  end

  def test_transform2
    assert style = Nokogiri::XSLT(File.open(XSLT_FILE))
    assert result_doc = style.transform(@doc)
    assert result_doc.html?
    assert_equal "", result_doc.at_css("h1").content

    assert style = Nokogiri::XSLT(File.read(XSLT_FILE))
    assert result_doc = style.transform(@doc, ['title', '"Booyah"'])
    assert result_doc.html?
    assert_equal "Booyah", result_doc.at_css("h1").content

    assert result_string = style.apply_to(@doc, ['title', '"Booyah"'])
    assert_equal result_string, style.serialize(result_doc)
  end

  def test_transform_with_quote_params
    assert style = Nokogiri::XSLT(File.open(XSLT_FILE))
    assert result_doc = style.transform(@doc, Nokogiri::XSLT.quote_params(['title', 'Booyah']))
    assert result_doc.html?
    assert_equal "Booyah", result_doc.at_css("h1").content

    assert style = Nokogiri::XSLT.parse(File.read(XSLT_FILE))
    assert result_doc = style.transform(@doc, Nokogiri::XSLT.quote_params({'title' => 'Booyah'}))
    assert result_doc.html?
    assert_equal "Booyah", result_doc.at_css("h1").content
  end

  def test_quote_params
    h = {
      :sym   => %{xxx},
      'str'  => %{"xxx"},
      :sym2  => %{'xxx'},
      'str2' => %{x'x'x},
      :sym3  => %{x"x"x},
    }
    hh=h.dup
    result_hash = Nokogiri::XSLT.quote_params(h)
    assert_equal hh, h # non-destructive

    a=h.to_a.flatten
    result_array = Nokogiri::XSLT.quote_params(a)
    assert_equal h.to_a.flatten, a #non-destructive

    assert_equal  result_array, result_hash
  end

  if Nokogiri.uses_libxml? # By now, cannot get it working on JRuby.
    def test_exslt
      assert doc = Nokogiri::XML.parse(File.read(EXML_FILE))
      assert doc.xml?

      assert style = Nokogiri::XSLT.parse(File.read(EXSLT_FILE))
      params = {
        :p1 => 'xxx',
        :p2 => "x'x'x",
        :p3 => 'x"x"x',
        :p4 => '"xxx"'
      }
      result_doc = Nokogiri::XML.parse(style.apply_to(doc,
          Nokogiri::XSLT.quote_params(params)))

      assert_equal 'func-result', result_doc.at('/root/function').content
      assert_equal 3, result_doc.at('/root/max').content.to_i
      assert_match(
        /\d{4}-\d\d-\d\d([-|+]\d\d:\d\d)?/,
        result_doc.at('/root/date').content
        )
      result_doc.xpath('/root/params/*').each do  |p|
        assert_equal p.content, params[p.name.intern]
      end
      check_params result_doc, params
      result_doc = Nokogiri::XML.parse(style.apply_to(doc,
          Nokogiri::XSLT.quote_params(params.to_a.flatten)))
      check_params result_doc, params
    end
  end

  def test_xslt_parse_error
    xslt_str = <<-EOX
<xsl:stylesheet version="1.0"
 xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <!-- Not well-formed: -->
  <xsl:template match="/"/>
    <values>
      <xsl:for-each select="//*">
        <value>
          <xsl:value-of select="@id"/>
        </value>
      </xsl:for-each>
    </values>
  </xsl:template>
</xsl:stylesheet>}
    EOX
    assert_raises(RuntimeError) { Nokogiri::XSLT.parse(xslt_str) }
  end

  def test_passing_a_non_document_to_transform
    xsl = Nokogiri::XSLT('<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"></xsl:stylesheet>')
    assert_raises(ArgumentError) { xsl.transform("<div></div>") }
    assert_raises(ArgumentError) { xsl.transform(Nokogiri::HTML("").css("body")) }
  end

  def check_params result_doc, params
    result_doc.xpath('/root/params/*').each do  |p|
      assert_equal p.content, params[p.name.intern]
    end
  end
end
