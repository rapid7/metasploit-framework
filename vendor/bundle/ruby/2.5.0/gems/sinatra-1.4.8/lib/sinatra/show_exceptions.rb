begin
  require 'rack/show_exceptions'
rescue LoadError
  require 'rack/showexceptions'
end

module Sinatra
  # Sinatra::ShowExceptions catches all exceptions raised from the app it
  # wraps. It shows a useful backtrace with the sourcefile and clickable
  # context, the whole Rack environment and the request data.
  #
  # Be careful when you use this on public-facing sites as it could reveal
  # information helpful to attackers.
  class ShowExceptions < Rack::ShowExceptions
    @@eats_errors = Object.new
    def @@eats_errors.flush(*) end
    def @@eats_errors.puts(*) end

    def initialize(app)
      @app      = app
      @template = ERB.new(TEMPLATE)
    end

    def call(env)
      @app.call(env)
    rescue Exception => e
      errors, env["rack.errors"] = env["rack.errors"], @@eats_errors

      if prefers_plain_text?(env)
        content_type = "text/plain"
        exception = dump_exception(e)
      else
        content_type = "text/html"
        exception = pretty(env, e)
      end

      env["rack.errors"] = errors

      # Post 893a2c50 in rack/rack, the #pretty method above, implemented in
      # Rack::ShowExceptions, returns a String instead of an array.
      body = Array(exception)

      [
        500,
        {
          "Content-Type" => content_type,
          "Content-Length" => Rack::Utils.bytesize(body.join).to_s
        },
        body
      ]
    end

    private

    def prefers_plain_text?(env)
      !(Request.new(env).preferred_type("text/plain","text/html") == "text/html") &&
      [/curl/].index{|item| item =~ env["HTTP_USER_AGENT"]}
    end

    def frame_class(frame)
      if frame.filename =~ /lib\/sinatra.*\.rb/
        "framework"
      elsif (defined?(Gem) && frame.filename.include?(Gem.dir)) ||
            frame.filename =~ /\/bin\/(\w+)$/
        "system"
      else
        "app"
      end
    end

TEMPLATE = <<-HTML # :nodoc:
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
  <title><%=h exception.class %> at <%=h path %></title>

  <script type="text/javascript">
  //<!--
  function toggle(id) {
    var pre  = document.getElementById("pre-" + id);
    var post = document.getElementById("post-" + id);
    var context = document.getElementById("context-" + id);

    if (pre.style.display == 'block') {
      pre.style.display = 'none';
      post.style.display = 'none';
      context.style.background = "none";
    } else {
      pre.style.display = 'block';
      post.style.display = 'block';
      context.style.background = "#fffed9";
    }
  }

  function toggleBacktrace(){
    var bt = document.getElementById("backtrace");
    var toggler = document.getElementById("expando");

    if (bt.className == 'condensed') {
      bt.className = 'expanded';
      toggler.innerHTML = "(condense)";
    } else {
      bt.className = 'condensed';
      toggler.innerHTML = "(expand)";
    }
  }
  //-->
  </script>

<style type="text/css" media="screen">
  *                   {margin: 0; padding: 0; border: 0; outline: 0;}
  div.clear           {clear: both;}
  body                {background: #EEEEEE; margin: 0; padding: 0;
                       font-family: 'Lucida Grande', 'Lucida Sans Unicode',
                       'Garuda';}
  code                {font-family: 'Lucida Console', monospace;
                       font-size: 12px;}
  li                  {height: 18px;}
  ul                  {list-style: none; margin: 0; padding: 0;}
  ol:hover            {cursor: pointer;}
  ol li               {white-space: pre;}
  #explanation        {font-size: 12px; color: #666666;
                       margin: 20px 0 0 100px;}
/* WRAP */
  #wrap               {width: 1000px; background: #FFFFFF; margin: 0 auto;
                       padding: 30px 50px 20px 50px;
                       border-left: 1px solid #DDDDDD;
                       border-right: 1px solid #DDDDDD;}
/* HEADER */
  #header             {margin: 0 auto 25px auto;}
  #header img         {float: left;}
  #header #summary    {float: left; margin: 12px 0 0 20px; width:660px;
                       font-family: 'Lucida Grande', 'Lucida Sans Unicode';}
  h1                  {margin: 0; font-size: 36px; color: #981919;}
  h2                  {margin: 0; font-size: 22px; color: #333333;}
  #header ul          {margin: 0; font-size: 12px; color: #666666;}
  #header ul li strong{color: #444444;}
  #header ul li       {display: inline; padding: 0 10px;}
  #header ul li.first {padding-left: 0;}
  #header ul li.last  {border: 0; padding-right: 0;}
/* BODY */
  #backtrace,
  #get,
  #post,
  #cookies,
  #rack               {width: 980px; margin: 0 auto 10px auto;}
  p#nav               {float: right; font-size: 14px;}
/* BACKTRACE */
  a#expando           {float: left; padding-left: 5px; color: #666666;
                      font-size: 14px; text-decoration: none; cursor: pointer;}
  a#expando:hover     {text-decoration: underline;}
  h3                  {float: left; width: 100px; margin-bottom: 10px;
                       color: #981919; font-size: 14px; font-weight: bold;}
  #nav a              {color: #666666; text-decoration: none; padding: 0 5px;}
  #backtrace li.frame-info {background: #f7f7f7; padding-left: 10px;
                           font-size: 12px; color: #333333;}
  #backtrace ul       {list-style-position: outside; border: 1px solid #E9E9E9;
                       border-bottom: 0;}
  #backtrace ol       {width: 920px; margin-left: 50px;
                       font: 10px 'Lucida Console', monospace; color: #666666;}
  #backtrace ol li    {border: 0; border-left: 1px solid #E9E9E9;
                       padding: 2px 0;}
  #backtrace ol code  {font-size: 10px; color: #555555; padding-left: 5px;}
  #backtrace-ul li    {border-bottom: 1px solid #E9E9E9; height: auto;
                       padding: 3px 0;}
  #backtrace-ul .code {padding: 6px 0 4px 0;}
  #backtrace.condensed .system,
  #backtrace.condensed .framework {display:none;}
/* REQUEST DATA */
  p.no-data           {padding-top: 2px; font-size: 12px; color: #666666;}
  table.req           {width: 980px; text-align: left; font-size: 12px;
                       color: #666666; padding: 0; border-spacing: 0;
                       border: 1px solid #EEEEEE; border-bottom: 0;
                       border-left: 0;
                       clear:both}
  table.req tr th     {padding: 2px 10px; font-weight: bold;
                       background: #F7F7F7; border-bottom: 1px solid #EEEEEE;
                       border-left: 1px solid #EEEEEE;}
  table.req tr td     {padding: 2px 20px 2px 10px;
                       border-bottom: 1px solid #EEEEEE;
                       border-left: 1px solid #EEEEEE;}
/* HIDE PRE/POST CODE AT START */
  .pre-context,
  .post-context       {display: none;}

  table td.code       {width:750px}
  table td.code div   {width:750px;overflow:hidden}
</style>
</head>
<body>
  <div id="wrap">
    <div id="header">
      <img src="<%= env['SCRIPT_NAME'] %>/__sinatra__/500.png" alt="application error" height="161" width="313" />
      <div id="summary">
        <h1><strong><%=h exception.class %></strong> at <strong><%=h path %>
          </strong></h1>
        <h2><%=h exception.message %></h2>
        <ul>
          <li class="first"><strong>file:</strong> <code>
            <%=h frames.first.filename.split("/").last %></code></li>
          <li><strong>location:</strong> <code><%=h frames.first.function %>
            </code></li>
          <li class="last"><strong>line:
            </strong> <%=h frames.first.lineno %></li>
        </ul>
      </div>
      <div class="clear"></div>
    </div>

    <div id="backtrace" class='condensed'>
      <h3>BACKTRACE</h3>
      <p><a href="#" id="expando"
            onclick="toggleBacktrace(); return false">(expand)</a></p>
      <p id="nav"><strong>JUMP TO:</strong>
         <a href="#get-info">GET</a>
         <a href="#post-info">POST</a>
         <a href="#cookie-info">COOKIES</a>
         <a href="#env-info">ENV</a>
      </p>
      <div class="clear"></div>

      <ul id="backtrace-ul">

      <% id = 1 %>
      <% frames.each do |frame| %>
          <% if frame.context_line && frame.context_line != "#" %>

            <li class="frame-info <%= frame_class(frame) %>">
              <code><%=h frame.filename %></code> in
                <code><strong><%=h frame.function %></strong></code>
            </li>

            <li class="code <%= frame_class(frame) %>">
              <% if frame.pre_context %>
              <ol start="<%=h frame.pre_context_lineno + 1 %>"
                  class="pre-context" id="pre-<%= id %>"
                  onclick="toggle(<%= id %>);">
                <% frame.pre_context.each do |line| %>
                <li class="pre-context-line"><code><%=h line %></code></li>
                <% end %>
              </ol>
              <% end %>

              <ol start="<%= frame.lineno %>" class="context" id="<%= id %>"
                  onclick="toggle(<%= id %>);">
                <li class="context-line" id="context-<%= id %>"><code><%=
                  h frame.context_line %></code></li>
              </ol>

              <% if frame.post_context %>
              <ol start="<%=h frame.lineno + 1 %>" class="post-context"
                  id="post-<%= id %>" onclick="toggle(<%= id %>);">
                <% frame.post_context.each do |line| %>
                <li class="post-context-line"><code><%=h line %></code></li>
                <% end %>
              </ol>
              <% end %>
              <div class="clear"></div>
            </li>

          <% end %>

        <% id += 1 %>
      <% end %>

      </ul>
    </div> <!-- /BACKTRACE -->

    <div id="get">
      <h3 id="get-info">GET</h3>
      <% if req.GET and not req.GET.empty? %>
        <table class="req">
          <tr>
            <th>Variable</th>
            <th>Value</th>
          </tr>
           <% req.GET.sort_by { |k, v| k.to_s }.each { |key, val| %>
          <tr>
            <td><%=h key %></td>
            <td class="code"><div><%=h val.inspect %></div></td>
          </tr>
          <% } %>
        </table>
      <% else %>
        <p class="no-data">No GET data.</p>
      <% end %>
      <div class="clear"></div>
    </div> <!-- /GET -->

    <div id="post">
      <h3 id="post-info">POST</h3>
      <% if req.POST and not req.POST.empty? %>
        <table class="req">
          <tr>
            <th>Variable</th>
            <th>Value</th>
          </tr>
          <% req.POST.sort_by { |k, v| k.to_s }.each { |key, val| %>
          <tr>
            <td><%=h key %></td>
            <td class="code"><div><%=h val.inspect %></div></td>
          </tr>
          <% } %>
        </table>
      <% else %>
        <p class="no-data">No POST data.</p>
      <% end %>
      <div class="clear"></div>
    </div> <!-- /POST -->

    <div id="cookies">
      <h3 id="cookie-info">COOKIES</h3>
      <% unless req.cookies.empty? %>
        <table class="req">
          <tr>
            <th>Variable</th>
            <th>Value</th>
          </tr>
          <% req.cookies.each { |key, val| %>
            <tr>
              <td><%=h key %></td>
              <td class="code"><div><%=h val.inspect %></div></td>
            </tr>
          <% } %>
        </table>
      <% else %>
        <p class="no-data">No cookie data.</p>
      <% end %>
      <div class="clear"></div>
    </div> <!-- /COOKIES -->

    <div id="rack">
      <h3 id="env-info">Rack ENV</h3>
      <table class="req">
        <tr>
          <th>Variable</th>
          <th>Value</th>
        </tr>
         <% env.sort_by { |k, v| k.to_s }.each { |key, val| %>
         <tr>
           <td><%=h key %></td>
           <td class="code"><div><%=h val %></div></td>
         </tr>
         <% } %>
      </table>
      <div class="clear"></div>
    </div> <!-- /RACK ENV -->

    <p id="explanation">You're seeing this error because you have
enabled the <code>show_exceptions</code> setting.</p>
  </div> <!-- /WRAP -->
  </body>
</html>
HTML
  end
end
