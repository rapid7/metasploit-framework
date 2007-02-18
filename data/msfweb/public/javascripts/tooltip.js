// Singleton class TooltipWindow
// This class works with special className. The tooltip content could be in your HTML page as an hidden element or
// can be retreive by an AJAX call.
//
// To work, You just need to set two class name on elements that should show tooltips
// - One to say to TooltipManager that this element must have a tooltip ('tooltip' by default)
// - Another to indicate how to find the tooltip content
//   It could be html_XXXX if tootltip content is somewhere hidden in your page, XXX must be DOM ID of this hidden element
//   It could be ajax_XXXX if tootltip content must be find by an ajax request, XXX will be the string send as id parameter to your server. 
// Check samples/tooltips/tooltip.html to see how it works
//
TooltipManager = {
  options: {cssClassName: 'tooltip', delayOver: 200, delayOut: 1000, shiftX: 10, shiftY: 10,
            className: 'alphacube', width: 200, height: null, 
            draggable: false, minimizable: false, maximizable: false, showEffect: Element.show, hideEffect: Element.hide},
  ajaxInfo: null,
  elements: null,
  showTimer: null,
  hideTimer: null,

  // Init tooltip manager
  // parameters:
  // - cssClassName (string) : CSS class name where tooltip should be shown. 
  // - ajaxOptions  (hash)   : Ajax options for ajax tooltip. 
  //                           For examples {url: "/tooltip/get.php", options: {method: 'get'}} 
  //                           see Ajax.Request documentation for details
  //- tooltipOptions (hash)  : available keys
  //                           - delayOver: int in ms (default 10) delay before showing tooltip
  //                           - delayOut:  int in ms (default 1000) delay before hidding tooltip
  //                           - shiftX:    int in pixels (default 10) left shift of the tooltip window 
  //                           - shiftY:    int in pixels (default 10) top shift of the tooltip window 
  //                           and All window options like showEffect: Element.show, hideEffect: Element.hide to remove animation
  //                           default: {className: 'alphacube', width: 200, height: null, draggable: false, minimizable: false, maximizable: false}
  
  init: function(cssClassName, ajaxInfo, tooltipOptions) {
    TooltipManager.options = Object.extend(TooltipManager.options, tooltipOptions || {});
    
    cssClassName = TooltipManager.options.cssClassName || "tooltip";
    TooltipManager.ajaxInfo = ajaxInfo;
    TooltipManager.elements = $$("." + cssClassName);
    TooltipManager.elements.each(function(element) {
      element = $(element)
      var info = TooltipManager._getInfo(element);
      if (info.ajax) {
        element.ajaxId = info.id;
        element.ajaxInfo = ajaxInfo;
      }
      else {
        element.tooltipElement = $(info.id);
      }
      element.observe("mouseover", TooltipManager._mouseOver);
      element.observe("mouseout", TooltipManager._mouseOut);
    });
    Windows.addObserver(this);
  },
  
  addHTML: function(element, tooltipElement) {
    element = $(element);
    tooltipElement = $(tooltipElement);
    element.tooltipElement = tooltipElement;
    
    element.observe("mouseover", TooltipManager._mouseOver);
    element.observe("mouseout", TooltipManager._mouseOut);
  },
  
  addAjax: function(element, ajaxInfo) {
    element = $(element);
    element.ajaxInfo = ajaxInfo;
    element.observe("mouseover", TooltipManager._mouseOver);
    element.observe("mouseout", TooltipManager._mouseOut);    
  },
    
  addURL: function(element, url, width, height) {
    element = $(element);
    element.url = url;
    element.frameWidth = width;
    element.frameHeight = height;
    element.observe("mouseover", TooltipManager._mouseOver);
    element.observe("mouseout", TooltipManager._mouseOut);    
  },
    
  close: function() {
    if (TooltipManager.tooltipWindow)
      TooltipManager.tooltipWindow.hide();
  },
  
  preloadImages: function(path, images, extension) {
    if (!extension)
      extension = ".gif";
      
    //preload images
    $A(images).each(function(i) {
      var image = new Image(); 
      image.src= path + "/" + i + extension; 
    });
  },
  
  _showTooltip: function(element) {
    if (this.element == element)
      return;
    // Get original element
    while (element && (!element.tooltipElement && !element.ajaxInfo && !element.url)) 
      element = element.parentNode;
    this.element = element;
    
    TooltipManager.showTimer = null;
    if (TooltipManager.hideTimer)
      clearTimeout(TooltipManager.hideTimer);
    
    var position = Position.cumulativeOffset(element);
    var dimension = element.getDimensions();

    if (! this.tooltipWindow)
      this.tooltipWindow = new Window("__tooltip__", TooltipManager.options);
      
    this.tooltipWindow.hide();
    this.tooltipWindow.setLocation(position[1] + dimension.height + TooltipManager.options.shiftY, position[0] + TooltipManager.options.shiftX);

    Event.observe(this.tooltipWindow.element, "mouseover", function(event) {TooltipManager._tooltipOver(event, element)});
    Event.observe(this.tooltipWindow.element, "mouseout", function(event) {TooltipManager._tooltipOut(event, element)});

    // Reset width/height for computation
    this.tooltipWindow.height = TooltipManager.options.height;
    this.tooltipWindow.width = TooltipManager.options.width;

    // Ajax content
    if (element.ajaxInfo) {
      var p = element.ajaxInfo.options.parameters;
      var saveParam = p;
      
      // Set by CSS
      if (element.ajaxId) {
        if (p)
          p += "&id=" + element.ajaxId;
        else
          p = "id=" + element.ajaxId;
      }
      element.ajaxInfo.options.parameters = p || "";
      this.tooltipWindow.setHTMLContent("");
      this.tooltipWindow.setAjaxContent(element.ajaxInfo.url, element.ajaxInfo.options);
      element.ajaxInfo.options.parameters = saveParam;    
    } 
    // URL content
    else if (element.url) {
      this.tooltipWindow.setURL(element.url);
      this.tooltipWindow.setSize(element.frameWidth, element.frameHeight);

      // Set tooltip size
      this.tooltipWindow.height = element.frameHeight;
      this.tooltipWindow.width = element.frameWidth;
    }
    // HTML content
    else
      this.tooltipWindow.setHTMLContent(element.tooltipElement.innerHTML);

    if (!element.ajaxInfo) 
      this.tooltipWindow.show();
  },
  
  _hideTooltip: function(element) {
    if (this.tooltipWindow) {
      this.tooltipWindow.hide();
      this.element = null;
    }
  },
  
  _mouseOver: function (event) {
    var element = Event.element(event);
    if (TooltipManager.showTimer) 
      clearTimeout(TooltipManager.showTimer);
    
    TooltipManager.showTimer = setTimeout(function() {TooltipManager._showTooltip(element)}, TooltipManager.options.delayOver)
  },
  
  _mouseOut: function(event) {
    var element = Event.element(event);
    if (TooltipManager.showTimer) {
      clearTimeout(TooltipManager.showTimer);
      TooltipManager.showTimer = null;
      return;
    }
    if (TooltipManager.tooltipWindow)
      TooltipManager.hideTimer = setTimeout(function() {TooltipManager._hideTooltip(element)}, TooltipManager.options.delayOut)
  },
  
  _tooltipOver: function(event, element) {
    if (TooltipManager.hideTimer) {
      clearTimeout(TooltipManager.hideTimer);
      TooltipManager.hideTimer = null;
    }
  },
  
  _tooltipOut: function(event, element) {
    if (TooltipManager.hideTimer == null)
      TooltipManager.hideTimer = setTimeout(function() {TooltipManager._hideTooltip(element)}, TooltipManager.options.delayOut)
  },
  
  _getInfo: function(element) {
    // Find html_ for static content
    var id = element.className.split(' ').detect(function(name) {return name.indexOf("html_") == 0});
    var ajax = true;
    if (id)
      ajax = false;
    else 
      // Find ajax_ for ajax content
      id = element.className.split(' ').detect(function(name) {return name.indexOf("ajax_") == 0});
    
    id = id.substr(id.indexOf('_')+1, id.length)
    return id ? {ajax: ajax, id: id} : null;
  },
  
  onBeforeShow: function(eventName, win) {
     var top = parseFloat(win.getLocation().top);
     var dim = win.element.getDimensions();
    
     if (top + dim.height > TooltipManager._getScrollTop() + TooltipManager._getPageHeight()) {
       var position = Position.cumulativeOffset(this.element);

       var top = position[1] - TooltipManager.options.shiftY - dim.height;
       win.setLocation(top, position[0] + TooltipManager.options.shiftX)
     }
   },

	_getPageWidth: function(){
		return window.innerWidth || document.documentElement.clientWidth || 0;
	},
	
	_getPageHeight: function(){
		return window.innerHeight || document.documentElement.clientHeight || 0;
	},

	_getScrollTop: function(){
		return document.documentElement.scrollTop || window.pageYOffset || 0;
	},

	_getScrollLeft: function(){
		return document.documentElement.scrollLeft || window.pageXOffset || 0;
	}	
};
