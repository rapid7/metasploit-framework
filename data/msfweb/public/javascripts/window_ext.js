// Copyright (c) 2006 Sébastien Gruhier (http://xilinus.com, http://itseb.com)
// YOU MUST INCLUDE window.js BEFORE
//
// Object to store hide/show windows status in a cookie
// Just add at the end of your HTML file this javascript line: WindowStore.init()
WindowStore = {
  doSetCookie: false,
  cookieName: "__window_store__",
  expired: null,
  
  // Init function with two optional parameters
  // - cookieName (default = __window_store__)
  // - expiration date (default 3 years from now)
  init: function(cookieName, expired) {
    WindowStore.cookieName = cookieName || WindowStore.cookieName

    if (! expired) {
      var today = new Date();
      today.setYear(today.getYear()+1903);
      WindowStore.expired = today;
    }
    else
      WindowStore.expired = expired;

    Windows.windows.each(function(win) {
      win.setCookie(win.getId(), WindowStore.expired);
    });

    // Create observer on show/hide events
    var myObserver = {
    	onShow: function(eventName, win) {
    	  WindowStore._saveCookie();
    	},
    	onHide: function(eventName, win) {
    	  WindowStore._saveCookie();
    	}
    }
    Windows.addObserver(myObserver);

    WindowStore._restoreWindows();
    WindowStore._saveCookie();
  },
  
  show: function(win) {
    eval("var cookie = " + WindowUtilities.getCookie(Windows.cookieName));
    if (cookie != null) {
      if (cookie[win.getId()])
        win.show();
    }
    else
      win.show();
  },

  // Function to store windows show/hide status in a cookie 
  _saveCookie: function() {
    if (!doSetCookie)
      return;
    
    var cookieValue = "{";
    Windows.windows.each(function(win) {
      if (cookieValue != "{")
        cookieValue += ","
      cookieValue += win.getId() + ": " + win.isVisible();
    });
    cookieValue += "}"
  
    WindowUtilities.setCookie(cookieValue, [WindowStore.cookieName, WindowStore.expired]);  
  },

  // Function to restore windows show/hide status from a cookie if exists
  _restoreWindows: function() {
    eval("var cookie = " + WindowUtilities.getCookie(Windows.cookieName));
    if (cookie != null) {
      doSetCookie = false;
      Windows.windows.each(function(win) {
        if (cookie[win.getId()])
          win.show();
      });
    }
    doSetCookie = true;
  }
}

// Object to set a close key an all windows
WindowCloseKey = {
  keyCode: Event.KEY_ESC,
  
  init: function(keyCode) {
    if (keyCode)
      WindowCloseKey.keyCode = keyCode;
    Event.observe(document, 'keydown', this._closeCurrentWindow.bindAsEventListener(this));
  },
  
  _closeCurrentWindow: function(event) {
    var e = event || window.event
  	var characterCode = e.which || e.keyCode;
  	var win = Windows.focusedWindow;
    if (characterCode == WindowCloseKey.keyCode && win) {
      if (win.cancelCallback) 
        Dialog.cancelCallback();      
      else if (win.okCallback) 
        Dialog.okCallback();
      else
        Windows.close(Windows.focusedWindow.getId());
    }
  }
}