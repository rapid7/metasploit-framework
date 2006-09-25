/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.graphics.Colorspace");

dojo.require("dojo.lang");
dojo.require("dojo.math.matrix");

//
// to convert to YUV:
//   c.whitePoint = 'D65';
//   c.RGBWorkingSpace = 'pal_secam_rgb';
//   var out = c.convert([r,g,b], 'RGB', 'XYZ');
//
// to convert to YIQ:
//   c.whitePoint = 'D65';
//   c.RGBWorkingSpace = 'ntsc_rgb';
//   var out = c.convert([r,g,b], 'RGB', 'XYZ');
//

dojo.graphics.Colorspace =function(){

	this.whitePoint = 'D65';
	this.stdObserver = '10';
	this.chromaticAdaptationAlg = 'bradford';
	this.RGBWorkingSpace = 's_rgb';
	this.useApproxCIELabMapping = 1; // see http://www.brucelindbloom.com/LContinuity.html

	this.chainMaps = {
		'RGB_to_xyY'  : ['XYZ'],
		'xyY_to_RGB'  : ['XYZ'],
		'RGB_to_Lab'  : ['XYZ'],
		'Lab_to_RGB'  : ['XYZ'],
		'RGB_to_LCHab': ['XYZ', 'Lab'],
		'LCHab_to_RGB': ['Lab'],
		'xyY_to_Lab'  : ['XYZ'],
		'Lab_to_xyY'  : ['XYZ'],
		'XYZ_to_LCHab': ['Lab'],
		'LCHab_to_XYZ': ['Lab'],
		'xyY_to_LCHab': ['XYZ', 'Lab'],
		'LCHab_to_xyY': ['Lab', 'XYZ'],
		'RGB_to_Luv'  : ['XYZ'],
		'Luv_to_RGB'  : ['XYZ'],
		'xyY_to_Luv'  : ['XYZ'],
		'Luv_to_xyY'  : ['XYZ'],
		'Lab_to_Luv'  : ['XYZ'],
		'Luv_to_Lab'  : ['XYZ'],
		'LCHab_to_Luv': ['Lab', 'XYZ'],
		'Luv_to_LCHab': ['XYZ', 'Lab'],
		'RGB_to_LCHuv'  : ['XYZ', 'Luv'],
		'LCHuv_to_RGB'  : ['Luv', 'XYZ'],
		'XYZ_to_LCHuv'  : ['Luv'],
		'LCHuv_to_XYZ'  : ['Luv'],
		'xyY_to_LCHuv'  : ['XYZ', 'Luv'],
		'LCHuv_to_xyY'  : ['Luv', 'XYZ'],
		'Lab_to_LCHuv'  : ['XYZ', 'Luv'],
		'LCHuv_to_Lab'  : ['Luv', 'XYZ'],
		'LCHab_to_LCHuv': ['Lab', 'XYZ', 'Luv'],
		'LCHuv_to_LCHab': ['Luv', 'XYZ', 'Lab'],
		'XYZ_to_CMY'    : ['RGB'],
		'CMY_to_XYZ'    : ['RGB'],
		'xyY_to_CMY'    : ['RGB'],
		'CMY_to_xyY'    : ['RGB'],
		'Lab_to_CMY'    : ['RGB'],
		'CMY_to_Lab'    : ['RGB'],
		'LCHab_to_CMY'  : ['RGB'],
		'CMY_to_LCHab'  : ['RGB'],
		'Luv_to_CMY'    : ['RGB'],
		'CMY_to_Luv'    : ['RGB'],
		'LCHuv_to_CMY'  : ['RGB'],
		'CMY_to_LCHuv'  : ['RGB'],
		'XYZ_to_HSL'    : ['RGB'],
		'HSL_to_XYZ'    : ['RGB'],
		'xyY_to_HSL'    : ['RGB'],
		'HSL_to_xyY'    : ['RGB'],
		'Lab_to_HSL'    : ['RGB'],
		'HSL_to_Lab'    : ['RGB'],
		'LCHab_to_HSL'  : ['RGB'],
		'HSL_to_LCHab'  : ['RGB'],
		'Luv_to_HSL'    : ['RGB'],
		'HSL_to_Luv'    : ['RGB'],
		'LCHuv_to_HSL'  : ['RGB'],
		'HSL_to_LCHuv'  : ['RGB'],
		'CMY_to_HSL'    : ['RGB'],
		'HSL_to_CMY'    : ['RGB'],
		'CMYK_to_HSL'   : ['RGB'],
		'HSL_to_CMYK'   : ['RGB'],
		'XYZ_to_HSV'    : ['RGB'],
		'HSV_to_XYZ'    : ['RGB'],
		'xyY_to_HSV'    : ['RGB'],
		'HSV_to_xyY'    : ['RGB'],
		'Lab_to_HSV'    : ['RGB'],
		'HSV_to_Lab'    : ['RGB'],
		'LCHab_to_HSV'  : ['RGB'],
		'HSV_to_LCHab'  : ['RGB'],
		'Luv_to_HSV'    : ['RGB'],
		'HSV_to_Luv'    : ['RGB'],
		'LCHuv_to_HSV'  : ['RGB'],
		'HSV_to_LCHuv'  : ['RGB'],
		'CMY_to_HSV'    : ['RGB'],
		'HSV_to_CMY'    : ['RGB'],
		'CMYK_to_HSV'   : ['RGB'],
		'HSV_to_CMYK'   : ['RGB'],
		'HSL_to_HSV'    : ['RGB'],
		'HSV_to_HSL'    : ['RGB'],
		'XYZ_to_CMYK'   : ['RGB'],
		'CMYK_to_XYZ'   : ['RGB'],
		'xyY_to_CMYK'   : ['RGB'],
		'CMYK_to_xyY'   : ['RGB'],
		'Lab_to_CMYK'   : ['RGB'],
		'CMYK_to_Lab'   : ['RGB'],
		'LCHab_to_CMYK' : ['RGB'],
		'CMYK_to_LCHab' : ['RGB'],
		'Luv_to_CMYK'   : ['RGB'],
		'CMYK_to_Luv'   : ['RGB'],
		'LCHuv_to_CMYK' : ['RGB'],
		'CMYK_to_LCHuv' : ['RGB']
	};


	return this;
}

dojo.graphics.Colorspace.prototype.convert = function(col, model_from, model_to){

	var k = model_from+'_to_'+model_to;

	if (this[k]){
		return this[k](col);
	}else{
		if (this.chainMaps[k]){

			var cur = model_from;
			var models = this.chainMaps[k].concat();
			models.push(model_to);

			for(var i=0; i<models.length; i++){

				col = this.convert(col, cur, models[i]);
				cur = models[i];
			}

			return col;

		}else{

			dojo.debug("Can't convert from "+model_from+' to '+model_to);
		}
	}
}

dojo.graphics.Colorspace.prototype.munge = function(keys, args){

	if (dojo.lang.isArray(args[0])){
		args = args[0];
	}

	var out = new Array();

	for (var i=0; i<keys.length; i++){
		out[keys.charAt(i)] = args[i];
	}

	return out;
}

dojo.graphics.Colorspace.prototype.getWhitePoint = function(){

	var x = 0;
	var y = 0;
	var t = 0;

	// ref: http://en.wikipedia.org/wiki/White_point
	// TODO: i need some good/better white point values

	switch(this.stdObserver){
		case '2' :
			switch(this.whitePoint){
				case 'E'   : x=1/3    ; y=1/3    ; t=5400; break; //Equal energy
				case 'D50' : x=0.34567; y=0.35850; t=5000; break;
				case 'D55' : x=0.33242; y=0.34743; t=5500; break;
				case 'D65' : x=0.31271; y=0.32902; t=6500; break;
				case 'D75' : x=0.29902; y=0.31485; t=7500; break;
				case 'A'   : x=0.44757; y=0.40745; t=2856; break; //Incandescent tungsten
				case 'B'   : x=0.34842; y=0.35161; t=4874; break;
				case 'C'   : x=0.31006; y=0.31616; t=6774; break;
				case '9300': x=0.28480; y=0.29320; t=9300; break; //Blue phosphor monitors
				case 'F2'  : x=0.37207; y=0.37512; t=4200; break; //Cool White Fluorescent
				case 'F7'  : x=0.31285; y=0.32918; t=6500; break; //Narrow Band Daylight Fluorescent
				case 'F11' : x=0.38054; y=0.37691; t=4000; break; //Narrow Band White Fluorescent
				default: dojo.debug('White point '+this.whitePoint+" isn't defined for Std. Observer "+this.strObserver);
			};
			break;
		case '10' :
			switch(this.whitePoint){
				case 'E'   : x=1/3    ; y=1/3    ; t=5400; break; //Equal energy
				case 'D50' : x=0.34773; y=0.35952; t=5000; break;
				case 'D55' : x=0.33411; y=0.34877; t=5500; break;
				case 'D65' : x=0.31382; y=0.33100; t=6500; break;
				case 'D75' : x=0.29968; y=0.31740; t=7500; break;
				case 'A'   : x=0.45117; y=0.40594; t=2856; break; //Incandescent tungsten
				case 'B'   : x=0.3498 ; y=0.3527 ; t=4874; break;
				case 'C'   : x=0.31039; y=0.31905; t=6774; break;
				case 'F2'  : x=0.37928; y=0.36723; t=4200; break; //Cool White Fluorescent
				case 'F7'  : x=0.31565; y=0.32951; t=6500; break; //Narrow Band Daylight Fluorescent
				case 'F11' : x=0.38543; y=0.37110; t=4000; break; //Narrow Band White Fluorescent
				default: dojo.debug('White point '+this.whitePoint+" isn't defined for Std. Observer "+this.strObserver);
			};
			break;
		default:
			dojo.debug("Std. Observer "+this.strObserver+" isn't defined");
	}

	var z = 1 - x - y;

	var wp = {'x':x, 'y':y, 'z':z, 't':t};

	wp.Y = 1;

	var XYZ = this.xyY_to_XYZ([wp.x, wp.y, wp.Y]);

	wp.X = XYZ[0];
	wp.Y = XYZ[1];
	wp.Z = XYZ[2];

	return wp
}

dojo.graphics.Colorspace.prototype.getPrimaries = function(){

	// ref: http://www.fho-emden.de/~hoffmann/ciexyz29082000.pdf
	// ref: http://www.brucelindbloom.com/index.html?Eqn_RGB_XYZ_Matrix.html

	var m = [];

	switch(this.RGBWorkingSpace){

		case 'adobe_rgb_1998'	: m = [2.2, 'D65', 0.6400, 0.3300, 0.297361, 0.2100, 0.7100, 0.627355, 0.1500, 0.0600, 0.075285]; break;
		case 'apple_rgb'	: m = [1.8, 'D65', 0.6250, 0.3400, 0.244634, 0.2800, 0.5950, 0.672034, 0.1550, 0.0700, 0.083332]; break;
		case 'best_rgb'		: m = [2.2, 'D50', 0.7347, 0.2653, 0.228457, 0.2150, 0.7750, 0.737352, 0.1300, 0.0350, 0.034191]; break;
		case 'beta_rgb'		: m = [2.2, 'D50', 0.6888, 0.3112, 0.303273, 0.1986, 0.7551, 0.663786, 0.1265, 0.0352, 0.032941]; break;
		case 'bruce_rgb'	: m = [2.2, 'D65', 0.6400, 0.3300, 0.240995, 0.2800, 0.6500, 0.683554, 0.1500, 0.0600, 0.075452]; break;
		case 'cie_rgb'		: m = [2.2, 'E'  , 0.7350, 0.2650, 0.176204, 0.2740, 0.7170, 0.812985, 0.1670, 0.0090, 0.010811]; break;
		case 'color_match_rgb'	: m = [1.8, 'D50', 0.6300, 0.3400, 0.274884, 0.2950, 0.6050, 0.658132, 0.1500, 0.0750, 0.066985]; break;
		case 'don_rgb_4'	: m = [2.2, 'D50', 0.6960, 0.3000, 0.278350, 0.2150, 0.7650, 0.687970, 0.1300, 0.0350, 0.033680]; break;
		case 'eci_rgb'		: m = [1.8, 'D50', 0.6700, 0.3300, 0.320250, 0.2100, 0.7100, 0.602071, 0.1400, 0.0800, 0.077679]; break;
		case 'ekta_space_ps5'	: m = [2.2, 'D50', 0.6950, 0.3050, 0.260629, 0.2600, 0.7000, 0.734946, 0.1100, 0.0050, 0.004425]; break;
		case 'ntsc_rgb'		: m = [2.2, 'C'  , 0.6700, 0.3300, 0.298839, 0.2100, 0.7100, 0.586811, 0.1400, 0.0800, 0.114350]; break;
		case 'pal_secam_rgb'	: m = [2.2, 'D65', 0.6400, 0.3300, 0.222021, 0.2900, 0.6000, 0.706645, 0.1500, 0.0600, 0.071334]; break;
		case 'pro_photo_rgb'	: m = [1.8, 'D50', 0.7347, 0.2653, 0.288040, 0.1596, 0.8404, 0.711874, 0.0366, 0.0001, 0.000086]; break;
		case 'smpte-c_rgb'	: m = [2.2, 'D65', 0.6300, 0.3400, 0.212395, 0.3100, 0.5950, 0.701049, 0.1550, 0.0700, 0.086556]; break;
		case 's_rgb'		: m = [2.2, 'D65', 0.6400, 0.3300, 0.212656, 0.3000, 0.6000, 0.715158, 0.1500, 0.0600, 0.072186]; break;
		case 'wide_gamut_rgb'	: m = [2.2, 'D50', 0.7350, 0.2650, 0.258187, 0.1150, 0.8260, 0.724938, 0.1570, 0.0180, 0.016875]; break;

		default: dojo.debug("RGB working space "+this.RGBWorkingSpace+" isn't defined");
	}

	var p = {};

	p.name = this.RGBWorkingSpace;
	p.gamma = m[0];
	p.wp = m[1];

	p.xr = m[2];
	p.yr = m[3];
	p.Yr = m[4];

	p.xg = m[5];
	p.yg = m[6];
	p.Yg = m[7];

	p.xb = m[8];
	p.yb = m[9];
	p.Yb = m[10];

	// if WP doesn't match current WP, convert the primaries over

	if (p.wp != this.whitePoint){

		var r = this.XYZ_to_xyY( this.chromaticAdaptation( this.xyY_to_XYZ([p.xr, p.yr, p.Yr]), p.wp, this.whitePoint ) );
		var g = this.XYZ_to_xyY( this.chromaticAdaptation( this.xyY_to_XYZ([p.xg, p.yg, p.Yg]), p.wp, this.whitePoint ) );
		var b = this.XYZ_to_xyY( this.chromaticAdaptation( this.xyY_to_XYZ([p.xb, p.yb, p.Yb]), p.wp, this.whitePoint ) );

		p.xr = r[0];
		p.yr = r[1];
		p.Yr = r[2];

		p.xg = g[0];
		p.yg = g[1];
		p.Yg = g[2];

		p.xb = b[0];
		p.yb = b[1];
		p.Yb = b[2];

		p.wp = this.whitePoint;
	}

	p.zr = 1 - p.xr - p.yr;
	p.zg = 1 - p.xg - p.yg;
	p.zb = 1 - p.xb - p.yb;

	return p;
}

dojo.graphics.Colorspace.prototype.epsilon = function(){

	return this.useApproxCIELabMapping ? 0.008856 : 216 / 24289;
}

dojo.graphics.Colorspace.prototype.kappa = function(){

	return this.useApproxCIELabMapping ? 903.3 : 24389 / 27;
}

dojo.graphics.Colorspace.prototype.XYZ_to_xyY = function(){
	var src = this.munge('XYZ', arguments);

	var sum = src.X + src.Y + src.Z;

	if (sum == 0){

		var wp = this.getWhitePoint();
		var x = wp.x;
		var y = wp.y;
	}else{
		var x = src.X / sum;
		var y = src.Y / sum;
	}

	var Y = src.Y;


	return [x, y, Y];
}

dojo.graphics.Colorspace.prototype.xyY_to_XYZ = function(){
	var src = this.munge('xyY', arguments);

	if (src.y == 0){

		var X = 0;
		var Y = 0;
		var Z = 0;
	}else{
		var X = (src.x * src.Y) / src.y;
		var Y = src.Y;
		var Z = ((1 - src.x - src.y) * src.Y) / src.y;
	}

	return [X, Y, Z];
}

dojo.graphics.Colorspace.prototype.RGB_to_XYZ = function(){
	var src = this.munge('RGB', arguments);

	var m = this.getRGB_XYZ_Matrix();
	var pr = this.getPrimaries();

	if (this.RGBWorkingSpace == 's_rgb'){

		var r = (src.R > 0.04045) ? Math.pow(((src.R + 0.055) / 1.055), 2.4) : src.R / 12.92;
		var g = (src.G > 0.04045) ? Math.pow(((src.G + 0.055) / 1.055), 2.4) : src.G / 12.92;
		var b = (src.B > 0.04045) ? Math.pow(((src.B + 0.055) / 1.055), 2.4) : src.B / 12.92;

	}else{

		var r = Math.pow(src.R, pr.gamma);
		var g = Math.pow(src.G, pr.gamma);
		var b = Math.pow(src.B, pr.gamma);
	}

	var XYZ = dojo.math.matrix.multiply([[r, g, b]], m);

	return [XYZ[0][0], XYZ[0][1], XYZ[0][2]];
}

dojo.graphics.Colorspace.prototype.XYZ_to_RGB = function(){
	var src = this.munge('XYZ', arguments);

	var mi = this.getXYZ_RGB_Matrix();
	var pr = this.getPrimaries();

	var rgb = dojo.math.matrix.multiply([[src.X, src.Y, src.Z]], mi);
	var r = rgb[0][0];
	var g = rgb[0][1];
	var b = rgb[0][2];

	if (this.RGBWorkingSpace == 's_rgb'){

		var R = (r > 0.0031308) ? (1.055 * Math.pow(r, 1.0/2.4)) - 0.055 : 12.92 * r;
		var G = (g > 0.0031308) ? (1.055 * Math.pow(g, 1.0/2.4)) - 0.055 : 12.92 * g;
		var B = (b > 0.0031308) ? (1.055 * Math.pow(b, 1.0/2.4)) - 0.055 : 12.92 * b;
	}else{
		var R = Math.pow(r, 1/pr.gamma);
		var G = Math.pow(g, 1/pr.gamma);
		var B = Math.pow(b, 1/pr.gamma);
	}

	return [R, G, B];
}

dojo.graphics.Colorspace.prototype.XYZ_to_Lab = function(){
	var src = this.munge('XYZ', arguments);

	var wp = this.getWhitePoint();

	var xr = src.X / wp.X;
	var yr = src.Y / wp.Y;
	var zr = src.Z / wp.Z;

	var fx = (xr > this.epsilon()) ? Math.pow(xr, 1/3) : (this.kappa() * xr + 16) / 116;
	var fy = (yr > this.epsilon()) ? Math.pow(yr, 1/3) : (this.kappa() * yr + 16) / 116;
	var fz = (zr > this.epsilon()) ? Math.pow(zr, 1/3) : (this.kappa() * zr + 16) / 116;

	var L = 116 * fy - 16;
	var a = 500 * (fx - fy);
	var b = 200 * (fy - fz);

	return [L, a, b];
}

dojo.graphics.Colorspace.prototype.Lab_to_XYZ = function(){
	var src = this.munge('Lab', arguments);

	var wp = this.getWhitePoint();

	var yr = (src.L > (this.kappa() * this.epsilon())) ? Math.pow((src.L + 16) / 116, 3) : src.L / this.kappa();

	var fy = (yr > this.epsilon()) ? (src.L + 16) / 116 : (this.kappa() * yr + 16) / 116;

	var fx = (src.a / 500) + fy;
	var fz = fy - (src.b / 200);

	var fxcube = Math.pow(fx, 3);
	var fzcube = Math.pow(fz, 3);

	var xr = (fxcube > this.epsilon()) ? fxcube : (116 * fx - 16) / this.kappa();
	var zr = (fzcube > this.epsilon()) ? fzcube : (116 * fz - 16) / this.kappa();

	var X = xr * wp.X;
	var Y = yr * wp.Y;
	var Z = zr * wp.Z;

	return [X, Y, Z];
}

dojo.graphics.Colorspace.prototype.Lab_to_LCHab = function(){
	var src = this.munge('Lab', arguments);

	var L = src.L;
	var C = Math.pow(src.a * src.a + src.b * src.b, 0.5);
	var H = Math.atan2(src.b, src.a) * (180 / Math.PI);

	if (H < 0){ H += 360; }
	if (H > 360){ H -= 360; }

	return [L, C, H];
}

dojo.graphics.Colorspace.prototype.LCHab_to_Lab = function(){
	var src = this.munge('LCH', arguments);

	var H_rad = src.H * (Math.PI / 180);

	var L = src.L;

	var a = src.C / Math.pow(Math.pow(Math.tan(H_rad), 2) + 1, 0.5);
	if ((90 < src.H) && (src.H < 270)){ a= -a; }

	var b = Math.pow(Math.pow(src.C, 2) - Math.pow(a, 2), 0.5);
	if (src.H > 180){ b = -b; }

	return [L, a, b];
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
//
// this function converts an XYZ color array (col) from one whitepoint (src_w) to another (dst_w)
//

dojo.graphics.Colorspace.prototype.chromaticAdaptation = function(col, src_w, dst_w){

	col = this.munge('XYZ', [col]);

	//
	// gather white point data for the source and dest
	//

	var old_wp = this.whitePoint;

	this.whitePoint = src_w;
	var wp_src = this.getWhitePoint();

	this.whitePoint = dst_w;
	var wp_dst = this.getWhitePoint();

	this.whitePoint = old_wp;


	//
	// get a transformation matricies
	//

	switch(this.chromaticAdaptationAlg){
		case 'xyz_scaling':
			var ma = [[1,0,0],[0,1,0],[0,0,1]];
			var mai = [[1,0,0],[0,1,0],[0,0,1]];
			break;
		case 'bradford':
			var ma = [[0.8951, -0.7502, 0.0389],[0.2664, 1.7135, -0.0685],[-0.1614, 0.0367, 1.0296]];
			var mai = [[0.986993, 0.432305, -0.008529],[-0.147054, 0.518360, 0.040043],[0.159963, 0.049291, 0.968487]];
			break;
		case 'von_kries':
			var ma = [[0.40024, -0.22630, 0.00000],[0.70760, 1.16532, 0.00000],[-0.08081, 0.04570, 0.91822]]
			var mai = [[1.859936, 0.361191, 0.000000],[-1.129382, 0.638812, 0.000000],[0.219897, -0.000006, 1.089064]]
			break;
		default:
			dojo.debug("The "+this.chromaticAdaptationAlg+" chromatic adaptation algorithm matricies are not defined");
	}


	//
	// calculate the cone response domains
	//

	var domain_src = dojo.math.matrix.multiply( [[wp_src.x, wp_src.y, wp_src.z]], ma);
	var domain_dst = dojo.math.matrix.multiply( [[wp_dst.x, wp_dst.y, wp_dst.z]], ma);


	//
	// construct the centre matrix
	//

	var centre = [
		[domain_dst[0][0]/domain_src[0][0], 0, 0],
		[0, domain_dst[0][1]/domain_src[0][1], 0],
		[0, 0, domain_dst[0][2]/domain_src[0][2]]
	];


	//
	// caclulate 'm'
	//

	var m = dojo.math.matrix.multiply( dojo.math.matrix.multiply( ma, centre ), mai );


	//
	// construct source color matrix
	//

	var dst = dojo.math.matrix.multiply( [[ col.X, col.Y, col.Z ]], m );

	return dst[0];
}

//////////////////////////////////////////////////////////////////////////////////////////////////////

dojo.graphics.Colorspace.prototype.getRGB_XYZ_Matrix = function(){

	var wp = this.getWhitePoint();
	var pr = this.getPrimaries();

	var Xr = pr.xr / pr.yr;
	var Yr = 1;
	var Zr = (1 - pr.xr - pr.yr) / pr.yr;

	var Xg = pr.xg / pr.yg;
	var Yg = 1;
	var Zg = (1 - pr.xg - pr.yg) / pr.yg;

	var Xb = pr.xb / pr.yb;
	var Yb = 1;
	var Zb = (1 - pr.xb - pr.yb) / pr.yb;

	var m1 = [[Xr, Yr, Zr],[Xg, Yg, Zg],[Xb, Yb, Zb]];
	var m2 = [[wp.X, wp.Y, wp.Z]];
	var sm = dojo.math.matrix.multiply(m2, dojo.math.matrix.inverse(m1));

	var Sr = sm[0][0];
	var Sg = sm[0][1];
	var Sb = sm[0][2];

	var m4 = [[Sr*Xr, Sr*Yr, Sr*Zr],
		  [Sg*Xg, Sg*Yg, Sg*Zg],
		  [Sb*Xb, Sb*Yb, Sb*Zb]];

	return m4;
}

dojo.graphics.Colorspace.prototype.getXYZ_RGB_Matrix = function(){

	var m = this.getRGB_XYZ_Matrix();

	return dojo.math.matrix.inverse(m);
}

dojo.graphics.Colorspace.prototype.XYZ_to_Luv = function(){

	var src = this.munge('XYZ', arguments);

	var wp = this.getWhitePoint();

	var ud = (4 * src.X) / (src.X + 15 * src.Y + 3 * src.Z);
	var vd = (9 * src.Y) / (src.X + 15 * src.Y + 3 * src.Z);

	var udr = (4 * wp.X) / (wp.X + 15 * wp.Y + 3 * wp.Z);
	var vdr = (9 * wp.Y) / (wp.X + 15 * wp.Y + 3 * wp.Z);

	var yr = src.Y / wp.Y;

	var L = (yr > this.epsilon()) ? 116 * Math.pow(yr, 1/3) - 16 : this.kappa() * yr;
	var u = 13 * L * (ud-udr);
	var v = 13 * L * (vd-vdr);

	return [L, u, v];
}

dojo.graphics.Colorspace.prototype.Luv_to_XYZ = function(){

	var src = this.munge('Luv', arguments);

	var wp = this.getWhitePoint();

	var uz = (4 * wp.X) / (wp.X + 15 * wp.Y + 3 * wp.Z);
	var vz = (9 * wp.Y) / (wp.X + 15 * wp.Y + 3 * wp.Z);

	var Y = (src.L > this.kappa() * this.epsilon()) ? Math.pow((src.L + 16) / 116, 3) : src.L / this.kappa();

	var a = (1 / 3) * (((52 * src.L) / (src.u + 13 * src.L * uz)) - 1);
	var b = -5 * Y;
	var c = - (1 / 3);
	var d = Y * (((39 * src.L) / (src.v + 13 * src.L * vz)) - 5);

	var X = (d - b) / (a - c);
	var Z = X * a + b;

	return [X, Y, Z];
}

dojo.graphics.Colorspace.prototype.Luv_to_LCHuv = function(){

	var src = this.munge('Luv', arguments);

	var L = src.L;
	var C = Math.pow(src.u * src.u + src.v * src.v, 0.5);
	var H = Math.atan2(src.v, src.u) * (180 / Math.PI);

	if (H < 0){ H += 360; }
	if (H > 360){ H -= 360; }

	return [L, C, H];
}

dojo.graphics.Colorspace.prototype.LCHuv_to_Luv = function(){

	var src = this.munge('LCH', arguments);

	var H_rad = src.H * (Math.PI / 180);

	var L = src.L;
	var u = src.C / Math.pow(Math.pow(Math.tan(H_rad), 2) + 1, 0.5);
	var v = Math.pow(src.C * src.C - u * u, 0.5);

	if ((90 < src.H) && (src.H < 270)){ u *= -1; }
	if (src.H > 180){ v *= -1; }

	return [L, u, v];
}

dojo.graphics.Colorspace.colorTemp_to_whitePoint = function(T){

	if (T < 4000){
		dojo.debug("Can't find a white point for temperatures under 4000K");
		return [0,0];
	}

	if (T > 25000){
		dojo.debug("Can't find a white point for temperatures over 25000K");
		return [0,0];
	}

	var T1 = T;
	var T2 = T * T;
	var T3 = T2 * T;

	var ten9 = Math.pow(10, 9);
	var ten6 = Math.pow(10, 6);
	var ten3 = Math.pow(10, 3);

	if (T <= 7000){

		var x = (-4.6070 * ten9 / T3) + (2.9678 * ten6 / T2) + (0.09911 * ten3 / T) + 0.244063;
	}else{
		var x = (-2.0064 * ten9 / T3) + (1.9018 * ten6 / T2) + (0.24748 * ten3 / T) + 0.237040;
	}

	var y = -3.000 * x * x + 2.870 * x - 0.275;

	return [x, y];
}

dojo.graphics.Colorspace.prototype.RGB_to_CMY = function(){

	var src = this.munge('RGB', arguments);

	var C = 1 - src.R;
	var M = 1 - src.G;
	var Y = 1 - src.B;

	return [C, M, Y];
}

dojo.graphics.Colorspace.prototype.CMY_to_RGB = function(){

	var src = this.munge('CMY', arguments);

	var R = 1 - src.C;
	var G = 1 - src.M;
	var B = 1 - src.Y;

	return [R, G, B];
}

dojo.graphics.Colorspace.prototype.RGB_to_CMYK = function(){

	var src = this.munge('RGB', arguments);

	var K = Math.min(1-src.R, 1-src.G, 1-src.B);
	var C = (1 - src.R - K) / (1 - K);
	var M = (1 - src.G - K) / (1 - K);
	var Y = (1 - src.B - K) / (1 - K);

	return [C, M, Y, K];
}

dojo.graphics.Colorspace.prototype.CMYK_to_RGB = function(){

	var src = this.munge('CMYK', arguments);

	var R = 1 - Math.min(1, src.C * (1-src.K) + src.K);
	var G = 1 - Math.min(1, src.M * (1-src.K) + src.K);
	var B = 1 - Math.min(1, src.Y * (1-src.K) + src.K);

	return [R, G, B];
}

dojo.graphics.Colorspace.prototype.CMY_to_CMYK = function(){

	var src = this.munge('CMY', arguments);

	var K = Math.min(src.C, src.M, src.Y);
	var C = (src.C - K) / (1 - K);
	var M = (src.M - K) / (1 - K);
	var Y = (src.Y - K) / (1 - K);

	return [C, M, Y, K];
}

dojo.graphics.Colorspace.prototype.CMYK_to_CMY = function(){

	var src = this.munge('CMYK', arguments);

	var C = Math.min(1, src.C * (1-src.K) + src.K);
	var M = Math.min(1, src.M * (1-src.K) + src.K);
	var Y = Math.min(1, src.Y * (1-src.K) + src.K);

	return [C, M, Y];
}

dojo.graphics.Colorspace.prototype.RGB_to_HSV = function(){

	var src = this.munge('RGB', arguments);

	// Based on C Code in "Computer Graphics -- Principles and Practice,"
	// Foley et al, 1996, p. 592. 

	var min = Math.min(src.R, src.G, src.B);
	var V = Math.max(src.R, src.G, src.B);

	var delta = V - min;

	var H = null;
	var S = (V == 0) ? 0 : delta / V;

	if (S == 0){
		H = 0;
	}else{
		if (src.R == V){
			H = 60 * (src.G - src.B) / delta;
		}else{
			if (src.G == V){
				H = 120 + 60 * (src.B - src.R) / delta;
			}else{
				if (src.B == V){
					// between magenta and cyan
					H = 240 + 60 * (src.R - src.G) / delta;
				}
			}
		}
		if (H < 0){
			H += 360;
		}
	}

	H = (H == 0) ? 360 : H;

	return [H, S, V];
}

dojo.graphics.Colorspace.prototype.HSV_to_RGB = function(){
 
	var src = this.munge('HSV', arguments);

	if (src.H == 360){ src.H = 0;}

	// Based on C Code in "Computer Graphics -- Principles and Practice,"
	// Foley et al, 1996, p. 593.

	var r = null;
	var g = null;
	var b = null;

	if (src.S == 0){
		// color is on black-and-white center line
		// achromatic: shades of gray
		var R = src.V;
		var G = src.V;
		var B = src.V;
	}else{
		// chromatic color
		var hTemp = src.H / 60;		// h is now IN [0,6]
		var i = Math.floor(hTemp);	// largest integer <= h
		var f = hTemp - i;		// fractional part of h

		var p = src.V * (1 - src.S);
		var q = src.V * (1 - (src.S * f));
		var t = src.V * (1 - (src.S * (1 - f)));

		switch(i){
			case 0: R = src.V; G = t    ; B = p    ; break;
			case 1: R = q    ; G = src.V; B = p    ; break;
			case 2: R = p    ; G = src.V; B = t    ; break;
			case 3: R = p    ; G = q    ; B = src.V; break;
			case 4: R = t    ; G = p    ; B = src.V; break;
			case 5: R = src.V; G = p    ; B = q    ; break;
		}
	}

	return [R, G, B];
}

dojo.graphics.Colorspace.prototype.RGB_to_HSL = function(){

	var src = this.munge('RGB', arguments);

	//
	// based on C code from http://astronomy.swin.edu.au/~pbourke/colour/hsl/
	//


	var min = Math.min(src.R, src.G, src.B);
	var max = Math.max(src.R, src.G, src.B);
	var delta = max - min;

	var H = 0;
	var S = 0;
	var L = (min + max) / 2;

	if ((L > 0) && (L < 1)){
		S = delta / ((L < 0.5) ? (2 * L) : (2 - 2 * L));
	}

	if (delta > 0) {
		if ((max == src.R) && (max != src.G)){
			H += (src.G - src.B) / delta;
		}
		if ((max == src.G) && (max != src.B)){
			H += (2 + (src.B - src.R) / delta);
		}
		if ((max == src.B) && (max != src.R)){
			H += (4 + (src.R - src.G) / delta);
		}
		H *= 60;
	}

	H = (H == 0) ? 360 : H;

	return [H, S, L];
}

dojo.graphics.Colorspace.prototype.HSL_to_RGB = function(){
 
	var src = this.munge('HSL', arguments);

	//
	// based on C code from http://astronomy.swin.edu.au/~pbourke/colour/hsl/
	//

	while (src.H < 0){ src.H += 360; }
	while (src.H >= 360){ src.H -= 360; }

	var R = 0;
	var G = 0;
	var B = 0;

	if (src.H < 120){
		R = (120 - src.H) / 60;
		G = src.H / 60;
		B = 0;
	}else if (src.H < 240){
		R = 0;
		G = (240 - src.H) / 60;
		B = (src.H - 120) / 60;
	}else{
		R = (src.H - 240) / 60;
		G = 0;
		B = (360 - src.H) / 60;
	}

	R = 2 * src.S * Math.min(R, 1) + (1 - src.S);
	G = 2 * src.S * Math.min(G, 1) + (1 - src.S);
	B = 2 * src.S * Math.min(B, 1) + (1 - src.S);

	if (src.L < 0.5){
		R = src.L * R;
		G = src.L * G;
		B = src.L * B;
	}else{
		R = (1 - src.L) * R + 2 * src.L - 1;
		G = (1 - src.L) * G + 2 * src.L - 1;
		B = (1 - src.L) * B + 2 * src.L - 1;
	}

	return [R, G, B];
}
