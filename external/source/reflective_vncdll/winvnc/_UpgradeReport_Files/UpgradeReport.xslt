<?xml version="1.0" encoding="utf-8" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl='urn:schemas-microsoft-com:xslt'>

    <xsl:key name="ProjectKey" match="Event" use="@Project" />

    <xsl:template match="Events" mode="createProjects">
        <projects>
            <xsl:for-each select="Event">
                <!--xsl:sort select="@Project" order="descending"/-->
                <xsl:if test="(1=position()) or (preceding-sibling::*[1]/@Project != @Project)">

                    <xsl:variable name="ProjectName" select="@Project"/>

                    <project>
                        <xsl:attribute name="name">
                            <xsl:value-of select="@Project"/>
                        </xsl:attribute> 

                        <xsl:if test="@Project=''">
                        <xsl:attribute name="solution">
                            <xsl:value-of select="@Solution"/>
                        </xsl:attribute> 
                        </xsl:if>

                        <xsl:for-each select="key('ProjectKey', $ProjectName)">
                            <!--xsl:sort select="@Source" /-->
                            <xsl:if test="(1=position()) or (preceding-sibling::*[1]/@Source != @Source)">

                                <source>
                                    <xsl:attribute name="name">
                                        <xsl:value-of select="@Source"/>
                                    </xsl:attribute>

                                    <xsl:variable name="Source">
                                        <xsl:value-of select="@Source"/>
                                    </xsl:variable>

                                    <xsl:for-each select="key('ProjectKey', $ProjectName)[ @Source = $Source ]">

                                        <event>
                                            <xsl:attribute name="error-level">
                                                <xsl:value-of select="@ErrorLevel"/>
                                            </xsl:attribute> 
                                            <xsl:attribute name="description">
                                                <xsl:value-of select="@Description"/>
                                            </xsl:attribute> 
                                        </event>
                                    </xsl:for-each>
                                </source>
                            </xsl:if>
                        </xsl:for-each>

                    </project>
                </xsl:if>
            </xsl:for-each>
        </projects>
    </xsl:template>

    <xsl:template match="projects">
    <xsl:for-each select="project">
    <xsl:sort select="@Name" order="ascending"/>
        <h2>
        <xsl:if test="@solution"><a _locID="Solution">Solution</a>: <xsl:value-of select="@solution"/></xsl:if>
        <xsl:if test="not(@solution)"><a _locID="Project">Project</a>: <xsl:value-of select="@name"/>
            <xsl:for-each select="source">
                <xsl:variable name="Hyperlink" select="@name"/>
            <xsl:for-each select="event[@error-level='4']">
            &#32;<A class="note"><xsl:attribute name="HREF"><xsl:value-of select="$Hyperlink"/></xsl:attribute><xsl:value-of select="@description"/></A>
                </xsl:for-each>
            </xsl:for-each>
        </xsl:if>
        </h2>

        <table cellpadding="2" cellspacing="0" width="98%" border="1" bordercolor="white" class="infotable">
            <tr>
                <td nowrap="1" class="header" _locID="Filename">Filename</td>
                <td nowrap="1" class="header" _locID="Status">Status</td>
                <td nowrap="1" class="header" _locID="Errors">Errors</td>
                <td nowrap="1" class="header" _locID="Warnings">Warnings</td>
            </tr>

            <xsl:for-each select="source">
                <xsl:sort select="@name" order="ascending"/>
                <xsl:variable name="source-id" select="generate-id(.)"/>

                <xsl:if test="count(event)!=count(event[@error-level='4'])">

                <tr class="row">
                    <td class="content">
                        <A HREF="javascript:"><xsl:attribute name="onClick">javascript:document.images['<xsl:value-of select="$source-id"/>'].click()</xsl:attribute><IMG border="0" _locID="IMG.alt" _locAttrData="alt"  alt="expand/collapse section" class="expandable" height="11" onclick="changepic()" src="_UpgradeReport_Files/UpgradeReport_Plus.gif" width="9" ><xsl:attribute name="name"><xsl:value-of select="$source-id"/></xsl:attribute><xsl:attribute name="child">src<xsl:value-of select="$source-id"/></xsl:attribute></IMG></A>&#32;<xsl:value-of select="@name"/> 
                    </td>
                    <td class="content">
                        <xsl:if test="count(event[@error-level='3'])=1">
                            <xsl:for-each select="event[@error-level='3']">
                            <xsl:if test="@description='Converted'"><a _locID="Converted1">Converted</a></xsl:if>
                            <xsl:if test="@description!='Converted'"><xsl:value-of select="@description"/></xsl:if>
                            </xsl:for-each>
                        </xsl:if>
                        <xsl:if test="count(event[@error-level='3'])!=1 and count(event[@error-level='3' and @description='Converted'])!=0"><a _locID="Converted2">Converted</a>
                        </xsl:if>
                    </td>
                    <td class="content"><xsl:value-of select="count(event[@error-level='2'])"/></td>
                    <td class="content"><xsl:value-of select="count(event[@error-level='1'])"/></td>
                </tr>

                <tr class="collapsed" bgcolor="#ffffff">
                    <xsl:attribute name="id">src<xsl:value-of select="$source-id"/></xsl:attribute>

                    <td colspan="7">
                        <table width="97%" border="1" bordercolor="#dcdcdc" rules="cols" class="issuetable">
                            <tr>
                                <td colspan="7" class="issuetitle" _locID="ConversionIssues">Conversion Issues - <xsl:value-of select="@name"/>:</td>
                            </tr>

                            <xsl:for-each select="event[@error-level!='3']">
                                <xsl:if test="@error-level!='4'">
                                <tr>
                                    <td class="issuenone" style="border-bottom:solid 1 lightgray">
                                        <xsl:value-of select="@description"/>
                                    </td>
                                </tr>
                                </xsl:if>
                            </xsl:for-each>
                        </table>
                    </td>
                </tr>
                </xsl:if>
            </xsl:for-each>

            <tr valign="top">
                <td class="foot">
                    <xsl:if test="count(source)!=1">
                        <xsl:value-of select="count(source)"/><a _locID="file1"> files</a>
                    </xsl:if>
                    <xsl:if test="count(source)=1">
                        <a _locID="file2">1 file</a>
                    </xsl:if>
                </td>
                <td class="foot">
					<a _locID="Converted3">Converted</a>:&#32;<xsl:value-of select="count(source/event[@error-level='3' and @description='Converted'])"/><BR />
					<a _locID="NotConverted">Not converted</a>:&#32;<xsl:value-of select="count(source) - count(source/event[@error-level='3' and @description='Converted'])"/>
                </td>
                <td class="foot"><xsl:value-of select="count(source/event[@error-level='2'])"/></td>
                <td class="foot"><xsl:value-of select="count(source/event[@error-level='1'])"/></td>
            </tr>
        </table>
    </xsl:for-each>
    </xsl:template>

    <xsl:template match="Property">
        <xsl:if test="@Name!='Date' and @Name!='Time' and @Name!='LogNumber' and @Name!='Solution'">
        <tr><td nowrap="1"><b><xsl:value-of select="@Name"/>: </b><xsl:value-of select="@Value"/></td></tr>
        </xsl:if>
    </xsl:template>

    <xsl:template match="UpgradeLog">
        <html>
            <head>
                <META HTTP-EQUIV="Content-Type" content="text/html; charset=utf-8" />
                <link rel="stylesheet" href="_UpgradeReport_Files\UpgradeReport.css" />
                <title _locID="ConversionReport0">Conversion Report&#32;
                    <xsl:if test="Properties/Property[@Name='LogNumber']">
                        <xsl:value-of select="Properties/Property[@Name='LogNumber']/@Value"/>
                    </xsl:if>
                </title>
                <script language="javascript">
                    function outliner () {
                        oMe = window.event.srcElement
                        //get child element
                        var child = document.all[event.srcElement.getAttribute("child",false)];
                        //if child element exists, expand or collapse it.
                        if (null != child)
                            child.className = child.className == "collapsed" ? "expanded" : "collapsed";
                    }

                    function changepic() {
                        uMe = window.event.srcElement;
                        var check = uMe.src.toLowerCase();
                        if (check.lastIndexOf("upgradereport_plus.gif") != -1)
                        {
                            uMe.src = "_UpgradeReport_Files/UpgradeReport_Minus.gif"
                        }
                        else
                        {
                            uMe.src = "_UpgradeReport_Files/UpgradeReport_Plus.gif"
                        }
                    }
                </script>
            </head>
            <body topmargin="0" leftmargin="0" rightmargin="0" onclick="outliner();">
                <h1 _locID="ConversionReport">Conversion Report - <xsl:value-of select="Properties/Property[@Name='Solution']/@Value"/></h1>

                <p><span class="note">
                <b _locID="TimeOfConversion">Time of Conversion:</b>&#32;&#32;<xsl:value-of select="Properties/Property[@Name='Date']/@Value"/>&#32;&#32;<xsl:value-of select="Properties/Property[@Name='Time']/@Value"/><br/>
                </span></p>

                <xsl:variable name="SortedEvents">
                    <Events>
                        <xsl:for-each select="Event">
                            <xsl:sort select="@Project" order="ascending"/>
                            <xsl:sort select="@Source" order="ascending"/>
                            <xsl:sort select="@ErrorLevel" order="ascending"/>
                            <Event>
                                <xsl:attribute name="Project"><xsl:value-of select="@Project"/> </xsl:attribute> 
                                <xsl:attribute name="Solution"><xsl:value-of select="/UpgradeLog/Properties/Property[@Name='Solution']/@Value"/> </xsl:attribute> 
                                <xsl:attribute name="Source"><xsl:value-of select="@Source"/> </xsl:attribute> 
                                <xsl:attribute name="ErrorLevel"><xsl:value-of select="@ErrorLevel"/> </xsl:attribute> 
                                <xsl:attribute name="Description"><xsl:value-of select="@Description"/> </xsl:attribute> 
                            </Event>
                        </xsl:for-each>     
                    </Events>
                </xsl:variable>
                
                <xsl:variable name="Projects">
                    <xsl:apply-templates select="msxsl:node-set($SortedEvents)/*" mode="createProjects"/>
                </xsl:variable>

                <xsl:apply-templates select="msxsl:node-set($Projects)/*"/>

                <p></p><p>
                <table class="note">
                    <tr>
                        <td nowrap="1">
                            <b _locID="ConversionSettings">Conversion Settings</b>
                        </td>
                    </tr>
                    <xsl:apply-templates select="Properties"/>
                </table></p>
            </body>
        </html>
    </xsl:template>
</xsl:stylesheet>
