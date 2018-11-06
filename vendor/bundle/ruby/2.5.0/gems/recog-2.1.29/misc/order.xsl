<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:output encoding="UTF-8" indent="yes" method="xml"/>
  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>
  <xsl:template match="fingerprints/fingerprint">
    <xsl:copy>
      <xsl:copy-of select="@*"/>
      <xsl:apply-templates select="description"/>
      <xsl:apply-templates select="example"/>
      <xsl:apply-templates select="param"/>
    </xsl:copy>
  </xsl:template>
</xsl:stylesheet>
