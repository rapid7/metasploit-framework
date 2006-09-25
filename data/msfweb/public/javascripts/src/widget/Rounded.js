/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.Rounded");
dojo.widget.tags.addParseTreeHandler("dojo:rounded");

dojo.require("dojo.widget.*");
dojo.require("dojo.widget.html.ContentPane");
dojo.require("dojo.html");
dojo.require("dojo.style");

/*
 *	The following script is derived (with permission) from curvyCorners,
 *	written by Cameron Cooke (CLA on file) and was adapted to Dojo by Brian
 *	Lucas (CLA on file)
 */

dojo.widget.Rounded = function() {
	dojo.widget.html.ContentPane.call(this);
}

dojo.inherits(dojo.widget.Rounded, dojo.widget.html.ContentPane);

dojo.lang.extend(dojo.widget.Rounded, {
	isSafari: dojo.render.html.safari,
	widgetType: "Rounded",
	boxMargin: "50px", // margin outside rounded corner box
	radius: 14, // radius of corners
	domNode: "",
	corners: "TR,TL,BR,BL", // corner string to render
	antiAlias: true, // false to disable anti-aliasing

	fillInTemplate: function(args, frag) {
		dojo.widget.Rounded.superclass.fillInTemplate.call(this, args, frag);

		dojo.style.insertCssFile(this.templateCssPath);

		// Magic to automatically calculate the box height/width if not supplied
		if (this.domNode.style.height<=0) {
			var minHeight = (this.radius*1)+this.domNode.clientHeight;
			this.domNode.style.height = minHeight+"px";
		}

		if (this.domNode.style.width<=0) {
			var minWidth = (this.radius*1)+this.domNode.clientWidth;
			this.domNode.style.width = minWidth+"px";
		}

		var cornersAvailable = ["TR", "TL", "BR", "BL"];
		var cornersPassed = this.corners.split(",");

		this.settings = {
			antiAlias: this.antiAlias
		};

		var setCorner = function(currentCorner) {
			var val = currentCorner.toLowerCase();
			if(dojo.lang.inArray(cornersPassed, currentCorner)) {
				this.settings[val] = { radius: this.radius, enabled: true };
			} else {
				this.settings[val] = { radius: 0 }
			}
		}
		dojo.lang.forEach(cornersAvailable, setCorner, this);

		this.domNode.style.margin = this.boxMargin;
		this.curvyCorners(this.settings);
		this.applyCorners();
	},

	// ------------- curvyCorners OBJECT

	curvyCorners: function(settings){	

		// Setup Globals
		this.box             = this.domNode;
		this.topContainer    = null;
		this.bottomContainer = null;
		this.masterCorners   = [];

		// Get box formatting details
		var boxHeight       = dojo.style.getStyle(this.box, "height");
		if(boxHeight=="") boxHeight="0px";
		var boxWidth        = dojo.style.getStyle(this.box, "width");
		var borderWidth     = dojo.style.getStyle(this.box, "borderTopWidth");
		if(borderWidth=="") borderWidth="0px";
		//alert(borderWidth);

		var borderColour    = dojo.style.getStyle(this.box, "borderTopColor");
		// Set to true if we have a border
		if(borderWidth>0) this.antiAlias=true;

		var boxColour       = dojo.style.getStyle(this.box, "backgroundColor");
		var backgroundImage = dojo.style.getStyle(this.box, "backgroundImage");
		var boxPosition     = dojo.style.getStyle(this.box, "position");

		// Set formatting propertes
		this.boxHeight       = parseInt(((boxHeight != "" && boxHeight != "auto" && boxHeight.indexOf("%") == -1)? boxHeight.substring(0, boxHeight.indexOf("px")) : this.box.scrollHeight));
		this.boxWidth        = parseInt(((boxWidth != "" && boxWidth != "auto" && boxWidth.indexOf("%") == -1)? boxWidth.substring(0, boxWidth.indexOf("px")) : this.box.scrollWidth));
		this.borderWidth     = parseInt(((borderWidth != "" && borderWidth.indexOf("px") !== -1)? borderWidth.slice(0, borderWidth.indexOf("px")) : 0));

		// DEBUG ME?

		//dojo.debug(this.rgb2Hex(boxColour));
		var test  = new dojo.graphics.color.Color(boxColour);
		//dojo.debug(test.toHex()); 

		this.boxColour       = ((boxColour != "" && boxColour != "transparent")? ((boxColour.substr(0, 3) == "rgb")? this.rgb2Hex(boxColour) : boxColour) : "#ffffff");
		this.borderColour    = ((borderColour != "" && borderColour != "transparent" && this.borderWidth > 0)? ((borderColour.substr(0, 3) == "rgb")? this.rgb2Hex(borderColour)  : borderColour) : this.boxColour);
		this.borderString    = this.borderWidth + "px" + " solid " + this.borderColour;
		this.backgroundImage = ((backgroundImage != "none")? backgroundImage : "");

		// Make box relative if not already absolute
		if(boxPosition != "absolute") this.box.style.position = "relative";

		//This method creates the corners and
		//applies them to the div element.

		this.applyCorners = function() {
			// Create top and bottom containers.
			// These will be used as a parent for the corners and bars.
			for(var t = 0; t < 2; t++) {
			    switch(t) {
			        // Top
			        case 0:
						// Only build top bar if a top corner is to be draw
						if(this.settings.tl.enabled || this.settings.tr.enabled ) {
							var newMainContainer = document.createElement("DIV");
			
							with(newMainContainer.style){
								width    = "100%";
								fontSize = "1px";
								overflow = "hidden";
								position = "absolute";
								//backgroundColor = "#FFFFC4";
								paddingLeft  = this.borderWidth + "px";
								paddingRight = this.borderWidth + "px";
								var topMaxRadius = Math.max(this.settings.tl ? this.settings.tl.radius : 0, this.settings.tr ? this.settings.tr.radius : 0);
								height = topMaxRadius + "px";
								top    = 0 - topMaxRadius + "px";
								left   = 0 - this.borderWidth + "px";
							}
							
							this.topContainer = this.box.appendChild(newMainContainer);
						}
			            break;
	
			        // Bottom
			        case 1:      
			            // Only build bottom bar if a top corner is to be draw
			            if(this.settings.bl.enabled || this.settings.br.enabled) {
							var newMainContainer = document.createElement("DIV");
							with(newMainContainer.style){
								width    = "100%";
								fontSize = "1px";
								overflow = "hidden";
								position = "absolute";
								//backgroundColor = "#FFFFC4";
								paddingLeft  = this.borderWidth + "px";
								paddingRight = this.borderWidth + "px";
								var botMaxRadius = Math.max(this.settings.bl ? this.settings.bl.radius : 0, this.settings.br ? this.settings.br.radius : 0);
								height  = botMaxRadius + "px";
								bottom  =  0 - botMaxRadius + "px";
								left    =  0 - this.borderWidth + "px";
							}
						this.bottomContainer = this.box.appendChild(newMainContainer);
			            }
		            break;
			    }
			}
	
			// Turn off current borders
			if(this.topContainer) this.box.style.borderTopWidth = "0px";
			if(this.bottomContainer) this.box.style.borderBottomWidth = "0px";
	
			// Create array of available corners
			var corners = ["tr", "tl", "br", "bl"];
		
			//Loop for each corner
	
			for(var i in corners) {
			    // Get current corner type from array
			    var cc = corners[i];

			    // Has the user requested the currentCorner be round?
			    if(!this.settings[cc]) {
			        // No
			        if(((cc == "tr" || cc == "tl") && this.topContainer != null) || ((cc == "br" || cc == "bl") && this.bottomContainer != null)) {
						// We need to create a filler div to fill the space upto the next horzontal corner.
						var newCorner = document.createElement("DIV");
		
						// Setup corners properties
						newCorner.style.position = "relative";
						newCorner.style.fontSize = "1px";
						newCorner.style.overflow = "hidden";
		
						// Add background image?
						if(this.backgroundImage == "") {
							newCorner.style.backgroundColor = this.boxColour;
						} else {
							newCorner.style.backgroundImage = this.backgroundImage;
						}

			            switch(cc) {
							case "tl":
								with(newCorner.style){
									height      = topMaxRadius - this.borderWidth + "px";
									marginRight = this.settings.tr.radius - (this.borderWidth*2) + "px";
									borderLeft  = this.borderString;
									borderTop   = this.borderString;
									left         = -this.borderWidth + "px";
								}
							break;
			
							case "tr":
								with(newCorner.style){
									height      = topMaxRadius - this.borderWidth + "px";
									marginLeft  = this.settings.tl.radius - (this.borderWidth*2) + "px";
									borderRight = this.borderString;
									borderTop   = this.borderString;
									backgroundPosition  = "-" + this.boxWidth + "px 0px";
									left         = this.borderWidth + "px";
								}
							break;
	
							case "bl":
								with(newCorner.style){
									height       = botMaxRadius - this.borderWidth + "px";
									marginRight  = this.settings.br.radius - (this.borderWidth*2) + "px";
									borderLeft   = this.borderString;
									borderBottom = this.borderString;
									left         = -this.borderWidth + "px";
								}
							break;
			
							case "br":
								with(newCorner.style){
									height       = botMaxRadius - this.borderWidth + "px";
									marginLeft   = this.settings.bl.radius - (this.borderWidth*2) + "px";
									borderRight  = this.borderString;
									borderBottom = this.borderString;
									left         = this.borderWidth + "px"
								}
							break;
			            }
			        }
			    } else {
			        /*
			        PERFORMANCE NOTE:

			        If more than one corner is requested and a corner has been already
			        created for the same radius then that corner will be used as a master and cloned.
			        The pixel bars will then be repositioned to form the new corner type.
			        All new corners start as a bottom right corner.
			        */
			        if(this.masterCorners[this.settings[cc].radius]) {
			            // Create clone of the master corner
			            var newCorner = this.masterCorners[this.settings[cc].radius].cloneNode(true);
			        } else {
			            // Yes, we need to create a new corner
			            var newCorner = document.createElement("DIV");
						with(newCorner.style){
							height = this.settings[cc].radius + "px";
							width  = this.settings[cc].radius + "px";
							position = "absolute";
							fontSize = "1px";
							overflow = "hidden";
						}
						// THE FOLLOWING BLOCK OF CODE CREATES A ROUNDED CORNER
						// ---------------------------------------------------- TOP
			
						// Get border radius
						var borderRadius = parseInt(this.settings[cc].radius - this.borderWidth);
			
						// Cycle the x-axis
						for(var intx = 0, j = this.settings[cc].radius; intx < j; intx++) {
							// Calculate the value of y1 which identifies the pixels inside the border
							if((intx +1) >= borderRadius) {
								var y1 = -1;
							} else {
								var y1 = (Math.floor(Math.sqrt(Math.pow(borderRadius, 2) - Math.pow((intx+1), 2))) - 1);
							}
			
							// Only calculate y2 and y3 if there is a border defined
							if(borderRadius != j) {
								if((intx) >= borderRadius) {
									var y2 = -1;
								} else {
									var y2 = Math.ceil(Math.sqrt(Math.pow(borderRadius,2) - Math.pow(intx, 2)));
								}
			
								if((intx+1) >= j) {
									var y3 = -1;
								} else {
									var y3 = (Math.floor(Math.sqrt(Math.pow(j ,2) - Math.pow((intx+1), 2))) - 1);
								}
							}

							// Calculate y4
							if((intx) >= j) {
								var y4 = -1;
							} else {
								var y4 = Math.ceil(Math.sqrt(Math.pow(j ,2) - Math.pow(intx, 2)));
							}

							// Draw bar on inside of the border with foreground colour
							if(y1 > -1) this.drawPixel(intx, 0, this.boxColour, 100, (y1+1), newCorner, -1, this.settings[cc].radius);
	
							// Only draw border/foreground antialiased pixels and border if there is a border defined
							if(borderRadius != j) {
								// Draw aa pixels?
								if(this.antiAlias) {
									// Cycle the y-axis
									for(var inty = (y1 + 1); inty < y2; inty++) {
										// For each of the pixels that need anti aliasing between the foreground and border colour draw single pixel divs
										if(this.backgroundImage != "") {					
											var borderFract = (this.pixelFraction(intx, inty, borderRadius) * 100);
					
											if (borderFract < 30) {
												this.drawPixel(intx, inty, this.borderColour, 100, 1, newCorner, 0, this.settings[cc].radius);
											} else {
												this.drawPixel(intx, inty, this.borderColour, 100, 1, newCorner, -1, this.settings[cc].radius);
											}
										} else {
											var pixelcolour = dojo.graphics.color.blend(this.boxColour, this.borderColour, this.pixelFraction(intx, inty, borderRadius));
											this.drawPixel(intx, inty, pixelcolour, 100, 1, newCorner, 0, this.settings[cc].radius);
										}
									}
								}

								// Draw bar for the border
								if(y3 >= y2) {
									if (y1 == -1) {
										y1 = 0;
									}
									this.drawPixel(intx, y2, this.borderColour, 100, (y3 - y2 + 1), newCorner, 0, this.settings[cc].radius);
								}	
								// Set the colour for the outside curve
								var outsideColour = this.borderColour;
							} else {
								// Set the coour for the outside curve
								var outsideColour = this.boxColour;
								var y3 = y1;
							}
			
							// Draw aa pixels?
							if(this.antiAlias) {		
								// Cycle the y-axis and draw the anti aliased pixels on the
								// outside of the curve
								for(var inty = (y3 + 1); inty < y4; inty++) {
									// For each of the pixels that need anti aliasing between 
									//the foreground/border colour & background draw single pixel divs
									this.drawPixel(intx, inty, outsideColour, (this.pixelFraction(intx, inty , j) * 100), 1, newCorner, ((this.borderWidth > 0)? 0 : -1), this.settings[cc].radius);
								}
							}
			            }

			            // END OF CORNER CREATION
			            // ---------------------------------------------------- END

			            // We now need to store the current corner in the masterConers array
			            this.masterCorners[this.settings[cc].radius] = newCorner.cloneNode(true);
			        }
			
					//Now we have a new corner we need to reposition all the pixels unless
					//the current corner is the bottom right.
			        if(cc != "br") {	
						// Loop through all children (pixel bars)
						for(var t = 0, k = newCorner.childNodes.length; t < k; t++) {
							// Get current pixel bar
							var pixelBar = newCorner.childNodes[t];
	
							// Get current top and left properties
							var pixelBarTop    = parseInt(pixelBar.style.top.substring(0, pixelBar.style.top.indexOf("px")));
							var pixelBarLeft   = parseInt(pixelBar.style.left.substring(0, pixelBar.style.left.indexOf("px")));
							var pixelBarHeight = parseInt(pixelBar.style.height.substring(0, pixelBar.style.height.indexOf("px")));
							
							// Reposition pixels
							if(cc == "tl" || cc == "bl") {
								pixelBar.style.left = this.settings[cc].radius -pixelBarLeft -1 + "px"; // Left
							}
							if(cc == "tr" || cc == "tl") {
								pixelBar.style.top =  this.settings[cc].radius -pixelBarHeight -pixelBarTop + "px"; // Top
							}
							var value;
					
							switch(cc) {
								case "tr":
									value = (-1 *( Math.abs((this.boxWidth - this.settings[cc].radius + this.borderWidth) + pixelBarLeft) - (Math.abs(this.settings[cc].radius -pixelBarHeight -pixelBarTop - this.borderWidth))));
									pixelBar.style.backgroundPosition  = value + "px";
									
								break;
				
								case "tl":
									value = (-1 *( Math.abs((this.settings[cc].radius -pixelBarLeft -1)  - this.borderWidth) - (Math.abs(this.settings[cc].radius -pixelBarHeight -pixelBarTop - this.borderWidth))));
									pixelBar.style.backgroundPosition  = value + "px";

								break;
				
								case "bl":
									value = (-1 *( Math.abs((this.settings[cc].radius -pixelBarLeft -1) - this.borderWidth) - (Math.abs((this.boxHeight + this.settings[cc].radius + pixelBarTop) -this.borderWidth))));
									pixelBar.style.backgroundPosition  = value + "px";

								break;
							}
						}
					}
				}
				if(newCorner) {
					// Position the container
					switch(cc) {
						case "tl":
							if(newCorner.style.position == "absolute") newCorner.style.top  = "0px";
							if(newCorner.style.position == "absolute") newCorner.style.left = "0px";
							if(this.topContainer) this.topContainer.appendChild(newCorner);
						break;

						case "tr":
							if(newCorner.style.position == "absolute") newCorner.style.top  = "0px";
							if(newCorner.style.position == "absolute") newCorner.style.right = "0px";
							if(this.topContainer) this.topContainer.appendChild(newCorner);
						break;
		
						case "bl":
							if(newCorner.style.position == "absolute") newCorner.style.bottom  = "0px";
							if(newCorner.style.position == "absolute") newCorner.style.left = "0px";
							if(this.bottomContainer) this.bottomContainer.appendChild(newCorner);
						break;
						
						case "br":
							if(newCorner.style.position == "absolute") newCorner.style.bottom = "0px";
							if(newCorner.style.position == "absolute") newCorner.style.right = "0px";
							if(this.bottomContainer) this.bottomContainer.appendChild(newCorner);
						break;
					}
				}
			}
			//The last thing to do is draw the rest of the filler DIVs.
			//We only need to create a filler DIVs when two corners have
			//diffrent radiuses in either the top or bottom container.
	
			// Find out which corner has the biiger radius and get the difference amount
			var radiusDiff = [];
			radiusDiff["t"] = this.settings.tl.enabled && this.settings.tr.enabled ? Math.abs(this.settings.tl.radius - this.settings.tr.radius) : 0;
			radiusDiff["b"] = this.settings.bl.enabled && this.settings.br.enabled ? Math.abs(this.settings.bl.radius - this.settings.br.radius) : 0;

			for(var z in radiusDiff) {
				if(radiusDiff[z]) {
					// Get the type of corner that is the smaller one
					var smallerCornerType = ((this.settings[z + "l"].radius < this.settings[z + "r"].radius)? z +"l" : z +"r");

					// First we need to create a DIV for the space under the smaller corner
					var newFiller = document.createElement("DIV");
					with(newFiller.style) {
						height = radiusDiff[z] + "px";
						width  =  this.settings[smallerCornerType].radius+ "px"
						position = "absolute";
						fontSize = "1px";
						overflow = "hidden";
						backgroundColor = this.boxColour;
					}

					// Position filler
					switch(smallerCornerType) {
						case "tl":
							with(newFiller.style) {
								bottom = "0px";
								left   = "0px";
								borderLeft = this.borderString;
							}
							this.topContainer.appendChild(newFiller);
						break;
	
						case "tr":
							with(newFiller.style) {
								bottom = "0px";
								right  = "0px";
								borderRight = this.borderString;
							}
							this.topContainer.appendChild(newFiller);
						break;

						case "bl":
							with(newFiller.style) {
								top    = "0px";
								left   = "0px";
								borderLeft = this.borderString;
							}
							this.bottomContainer.appendChild(newFiller);
						break;

						case "br":
							with(newFiller.style) {
								top    = "0px";
								right  = "0px";
								borderRight = this.borderString;
							}
							this.bottomContainer.appendChild(newFiller);
						break;
					}
			    }

				// Create the bar to fill the gap between each corner horizontally
				var newFillerBar = document.createElement("DIV");
				with(newFillerBar.style) {
					position = "relative";
					fontSize = "1px";
					overflow = "hidden";
					backgroundColor = this.boxColour;
				}

				switch(z) {
					case "t":
						// Top Bar
						if(this.topContainer) {
							with(newFillerBar.style) {
								height      = topMaxRadius - this.borderWidth + "px";
								marginLeft  = this.settings.tl.radius - this.borderWidth + "px";
								marginRight = this.settings.tr.radius - this.borderWidth + "px";
								borderTop   = this.borderString;
							}
						this.topContainer.appendChild(newFillerBar);
						}
					break;

					case "b":
						if(this.bottomContainer) {
						// Bottom Bar
						with(newFillerBar.style) {
							height       = botMaxRadius - this.borderWidth + "px";
							marginLeft   = this.settings.bl.radius - this.borderWidth + "px";
							marginRight  = this.settings.br.radius - this.borderWidth + "px";
							borderBottom = this.borderString;
						}
						this.bottomContainer.appendChild(newFillerBar);
					}
					break;
				}
			}
		}

		// This function draws the pixles
		this.drawPixel = function(intx, inty, colour, transAmount, height, newCorner, image, cornerRadius) {
			// Create pixel
			var pixel = document.createElement("DIV");

			
			// Section doesn't like with (pixel.style) { DEBUG?
			pixel.style.height   = height + "px";
			pixel.style.width    = "1px";
			pixel.style.position = "absolute";
			pixel.style.fontSize = "1px";
			pixel.style.overflow = "hidden";
			
			// Dont apply background image to border pixels
			if(image == -1 && this.backgroundImage != "") {
				pixel.style.backgroundImage = this.backgroundImage;
				pixel.style.backgroundPosition  = "-" + (this.boxWidth - (cornerRadius - intx) + this.borderWidth) + "px -" + ((this.boxHeight + cornerRadius + inty) -this.borderWidth) + "px";
			} else {
				pixel.style.backgroundColor = colour;
			}
			
			// Set opacity if the transparency is anything other than 100
			if (transAmount != 100) {
				dojo.style.setOpacity(pixel, transAmount);
			}
			// Set the pixels position
			pixel.style.top = inty + "px";
			pixel.style.left = intx + "px";
		
			newCorner.appendChild(pixel);
		}
	},

	//For a pixel cut by the line determines the fraction of the pixel on the 'inside' of the
	//line.  Returns a number between 0 and 1
	pixelFraction: function(x, y, r) {
		var pixelfraction = 0;
		
		//determine the co-ordinates of the two points on the perimeter of the pixel that the
		//circle crosses
		
		var xvalues = [];
		var yvalues = [];
		var point = 0;
		var whatsides = "";

		// x + 0 = Left
		var intersect = Math.sqrt((Math.pow(r,2) - Math.pow(x,2)));

		if ((intersect >= y) && (intersect < (y+1))) {
			whatsides = "Left";
			xvalues[point] = 0;
			yvalues[point] = intersect - y;
			point =  point + 1;
		}

		// y + 1 = Top
		var intersect = Math.sqrt((Math.pow(r,2) - Math.pow(y+1,2)));
		
		if ((intersect >= x) && (intersect < (x+1))) {
			whatsides = whatsides + "Top";
			xvalues[point] = intersect - x;
			yvalues[point] = 1;
			point = point + 1;
		}
		// x + 1 = Right
		var intersect = Math.sqrt((Math.pow(r,2) - Math.pow(x+1,2)));

		if ((intersect >= y) && (intersect < (y+1))) {
			whatsides = whatsides + "Right";
			xvalues[point] = 1;
			yvalues[point] = intersect - y;
			point =  point + 1;
		}
		// y + 0 = Bottom
		var intersect = Math.sqrt((Math.pow(r,2) - Math.pow(y,2)));

		if ((intersect >= x) && (intersect < (x+1))) {
			whatsides = whatsides + "Bottom";
			xvalues[point] = intersect - x;
			yvalues[point] = 0;
		}

	    //depending on which sides of the perimeter of the pixel the circle crosses calculate the
	    //fraction of the pixel inside the circle

		switch (whatsides) {
			case "LeftRight":
				pixelfraction = Math.min(yvalues[0],yvalues[1]) + ((Math.max(yvalues[0],yvalues[1]) - Math.min(yvalues[0],yvalues[1]))/2);
			break;
			
			case "TopRight":
				pixelfraction = 1-(((1-xvalues[0])*(1-yvalues[1]))/2);
			break;
			
			case "TopBottom":
				pixelfraction = Math.min(xvalues[0],xvalues[1]) + ((Math.max(xvalues[0],xvalues[1]) - Math.min(xvalues[0],xvalues[1]))/2);
			break;
			
			case "LeftBottom":
				pixelfraction = (yvalues[0]*xvalues[1])/2;
			break;
			
			default:
				pixelfraction = 1;
	    }
	    return pixelfraction;
	},

	// This function converts CSS rgb(x, x, x) to hexadecimal
	rgb2Hex: function (rgbColour) {
		try{	
			// Get array of RGB values
			var rgbArray = this.rgb2Array(rgbColour);
			
			// Get RGB values
			var red   = parseInt(rgbArray[0]);
			var green = parseInt(rgbArray[1]);
			var blue  = parseInt(rgbArray[2]);
			
			// Build hex colour code
			var hexColour = "#" + this.intToHex(red) + this.intToHex(green) + this.intToHex(blue);
		}
		catch(e){ alert("There was an error converting the RGB value to Hexadecimal in function rgb2Hex");
		}
		return hexColour;
	},

	//Converts a number to hexadecimal format

	intToHex: function (strNum) {
		var base = strNum / 16;
		var rem = strNum % 16;
		var base = base - (rem / 16);
		var baseS = this.makeHex(base);
		var remS = this.makeHex(rem);
		return baseS + '' + remS;
	},
	//gets the hex bits of a number

	makeHex: function(x) {
		if((x >= 0) && (x <= 9)) {
			return x;
		} else {
			switch(x) {
				case 10: return "A";
				case 11: return "B";
				case 12: return "C";
				case 13: return "D";
				case 14: return "E";
				case 15: return "F";
			}
		}
	},

	// Returns an array of rbg values
	rgb2Array: function(rgbColour) {
		// Remove rgb()
		var rgbValues = rgbColour.substring(4, rgbColour.indexOf(")"));
	
		// Split RGB into array
		var rgbArray = rgbValues.split(", ");
		return rgbArray;
	}
}); // end function
