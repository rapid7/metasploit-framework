var debugWindow = null;
function debug(text, reverse) {
	if (debugWindow == null)
 		return;

	time = "-"; //new Date();
	if (reverse) {
		$('debug').innerHTML = time + " " + text + "<br>"+ 	$('debug').innerHTML;
		debugWindow.getContent().scrollTop=0;
	}
	else {
		$('debug').innerHTML +=  time + " " + text + "<br>";
		debugWindow.getContent().scrollTop=10000; // Far away 
	}
}

function hideDebug() {
	if (debugWindow) {
		debugWindow.destroy();
		debugWindow = null;
	}
}

function showDebug(bShow) {
 if (debugWindow == null) {
  debugWindow = new Window('debug_window', {className: 'dialog',width:250, height:100, right:4, bottom:42, zIndex:1000, opacity:1, showEffect: Element.show, resizable: true, title: "Debug"})
  debugWindow.getContent().innerHTML = "<style>#debug_window .dialog_content {background:#000;}</style> <div id='debug'></div>";
  date=new Date;
    date.setMonth(date.getMonth()+3);
    
  //debugWindow.setCookie(null, date);
 }
 if( typeof bShow == 'undefined' || bShow)debugWindow.show()
}


function clearDebug() {
	if (debugWindow == null)
 		return;
	$('debug').innerHTML = "";
}

/**
 * document.createElement convenience wrapper
 *
 * The data parameter is an object that must have the "tag" key, containing
 * a string with the tagname of the element to create.  It can optionally have
 * a "children" key which can be: a string, "data" object, or an array of "data"
 * objects to append to this element as children.  Any other key is taken as an
 * attribute to be applied to this tag.
 *
 * Available under an MIT license:
 * http://www.opensource.org/licenses/mit-license.php
 *
 * @param {Object} data The data representing the element to create
 * @return {Element} The element created.
 */
function $E(data) {
  var el;
  if ('string'==typeof data) {
      el=document.createTextNode(data);
  } else {
    //create the element
    el=document.createElement(data.tag);
    delete(data.tag);

    //append the children
    if ('undefined'!=typeof data.children) {
      if ('string'==typeof data.children ||'undefined'==typeof data.children.length) {
        //strings and single elements
        el.appendChild($E(data.children));
      } else {
        //arrays of elements
        for (var i=0, child=null; 'undefined'!=typeof (child=data.children[i]); i++) {
            el.appendChild($E(child));
        }
      }
      delete(data.children);
    }

    //any other data is attributes
    for (attr in data) {
      el[attr]=data[attr];
    }
  }

  return el;
}

// FROM Nick Hemsley
var Debug = {
	inspectOutput: function (container, within) {
		within = within || debugWindow.getContent()
		
		if (debugWindow == null)
 			return;

		within.appendChild(container)
	},
	
	inspect: function(object) {
		var cont = $E({tag: "div", className: "inspector"})
		Debug.inspectObj(object, cont)
		debugWindow.getContent().appendChild(cont)
	},
	
	inspectObj: function (object, container) {
		for (prop in object) {
			Debug.inspectOutput(Debug.inspectable(object, prop), container)
		}
	},
	
	inspectable: function(object, prop) {
		cont = $E({tag: 'div', className: 'inspectable', children: [prop + " value: " + object[prop] ]})
		cont.toInspect = object[prop]
		Event.observe(cont, 'click', Debug.inspectClicked, false)
		return cont
	},
	
	inspectClicked: function(e) {
		Debug.inspectContained(Event.element(e))
		Event.stop(e)
	},
	
	inspectContained: function(container) {
		if (container.opened) {
			container.parentNode.removeChild(container.opened)
			delete(container.opened)
		} else {
			sibling = container.parentNode.insertBefore($E({tag: "div", className: "child"}), container.nextSibling)
			if (container.toInspect)
				Debug.inspectObj(container.toInspect, sibling)
			container.opened = sibling
		}
	}
}
var inspect = Debug.inspect;
