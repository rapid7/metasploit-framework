/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.math.matrix");

//
// some of this code is based on
// http://www.mkaz.com/math/MatrixCalculator.java
// (published under a BSD Open Source License)
//
// the rest is from my vague memory of matricies in school [cal]
//
// the copying of arguments is a little excessive, and could be trimmed back in
// the case where a function doesn't modify them at all (but some do!)
//

dojo.math.matrix.iDF = 0;

dojo.math.matrix.multiply = function(a, b){

	a = dojo.math.matrix.copy(a);
	b = dojo.math.matrix.copy(b);

	var ax = a[0].length;
	var ay = a.length;
	var bx = b[0].length;
	var by = b.length;

	if (ax != by){
		dojo.debug("Can't multiply matricies of sizes "+ax+','+ay+' and '+bx+','+by);
		return [[0]];
	}

	var c = [];

	for(var k=0; k<ay; k++){
		c[k] = [];
		for(var i=0; i<bx; i++){

			c[k][i] = 0;

			for(var m=0; m<ax; m++){

				c[k][i] += a[k][m]*b[m][i];
			}
		}
	}

	return c;
}

dojo.math.matrix.inverse = function(a){

	a = dojo.math.matrix.copy(a);

	// Formula used to Calculate Inverse:
	// inv(A) = 1/det(A) * adj(A)

	var tms = a.length;

	var m = dojo.math.matrix.create(tms, tms);
	var mm = dojo.math.matrix.adjoint(a);

	var det = dojo.math.matrix.determinant(a);
	var dd = 0;

	if (det == 0){
		dojo.debug("Determinant Equals 0, Not Invertible.");
		return [[0]];
	}else{
		dd = 1 / det;
	}

	for (var i = 0; i < tms; i++)
		for (var j = 0; j < tms; j++) {
			m[i][j] = dd * mm[i][j];
		}

	return m;
}

dojo.math.matrix.determinant = function(a){

	a = dojo.math.matrix.copy(a);

	if (a.length != a[0].length){
		dojo.debug("Can't calculate the determiant of a non-squre matrix!");
		return 0;
	}

	var tms = a.length;
	var det = 1;

	var b = dojo.math.matrix.upperTriangle(a);

	for (var i=0; i < tms; i++){
		det *= b[i][i];
	}

	det = det * dojo.math.matrix.iDF;

	return det;
}

dojo.math.matrix.upperTriangle = function(m){

	m = dojo.math.matrix.copy(m);

	var f1 = 0;
	var temp = 0;
	var tms = m.length;
	var v = 1;

	dojo.math.matrix.iDF = 1;

	for (var col = 0; col < tms - 1; col++) {
		for (var row = col + 1; row < tms; row++) {
			v = 1;

			var stop_loop = 0;

			// check if 0 in diagonal
 			while ((m[col][col] == 0) && !stop_loop){

				// if so switch until not
				if (col + v >= tms){

					// check if switched all rows
					dojo.math.matrix.iDF = 0;
					stop_loop = 1;
				}else{
					for (var c = 0; c < tms; c++) {
						temp = m[col][c];
						m[col][c] = m[col + v][c]; // switch rows
						m[col + v][c] = temp;
					}
					v++; // count row switchs
					dojo.math.matrix.iDF *= -1; // each switch changes determinant factor
				}
			}

			if (m[col][col] != 0) {
				f1 = (-1) * m[row][col] / m[col][col];
				for (var i = col; i < tms; i++) {
					m[row][i] = f1 * m[col][i] + m[row][i];
				}
			}
		}
	}

	return m;
}

dojo.math.matrix.create = function(a, b){
	var m = [];
	for(var i=0; i<b; i++){
		m[i] = [];
		for(var j=0; j<a; j++){
			m[i][j] = 0;
		}
	}
	return m;
}

dojo.math.matrix.adjoint = function(a){

	a = dojo.math.matrix.copy(a);

	var tms = a.length;

	if (a.length != a[0].length){
		dojo.debug("Can't find the adjoint of a non-square matrix");
		return [[0]];
	}

	if (tms == 1){
		dojo.debug("Can't find the adjoint of a 1x1 matrix");
		return [[0]];
	}

	var m = dojo.math.matrix.create(tms, tms);

	var ii = 0;
	var jj = 0;
	var ia = 0;
	var ja = 0;
	var det = 0;

	for (var i = 0; i < tms; i++){
		for (var j = 0; j < tms; j++){

			ia = 0;
			ja = 0;

			var ap = dojo.math.matrix.create(tms-1, tms-1);

			for (ii = 0; ii < tms; ii++) {
				for (jj = 0; jj < tms; jj++) {

					if ((ii != i) && (jj != j)) {
						ap[ia][ja] = a[ii][jj];
						ja++;
					}

				}

				if ((ii != i) && (jj != j)) {
					ia++;
				}
				ja = 0;
			}

			det = dojo.math.matrix.determinant(ap);
			m[i][j] = Math.pow(-1 , (i + j)) * det;
		}
	}

	m = dojo.math.matrix.transpose(m);

	return m;
}

dojo.math.matrix.transpose = function(a){

	a = dojo.math.matrix.copy(a);

	var m = dojo.math.matrix.create(a.length, a[0].length);

	for (var i = 0; i < a.length; i++)
		for (var j = 0; j < a[i].length; j++)
			m[j][i] = a[i][j];
	return m;
}

dojo.math.matrix.format = function(a){

	function format_int(x){
		var dp = 5;
		var fac = Math.pow(10 , dp);
		var a = Math.round(x*fac)/fac;
		var b = a.toString();
		if (b.charAt(0) != '-'){ b = ' ' + b;}
		var has_dp = 0;
		for(var i=1; i<b.length; i++){
			if (b.charAt(i) == '.'){ has_dp = 1; }
		}
		if (!has_dp){ b += '.'; }
		while(b.length < dp+3){ b += '0'; }
		return b;
	}

	var ya = a.length;
	var xa = a[0].length;

	var buffer = '';

	for (var y=0; y<ya; y++){
		buffer += '| ';
		for (var x=0; x<xa; x++){
			buffer += format_int(a[y][x]) + ' ';
		}
		buffer += '|\n';
	}

	return buffer;
}

dojo.math.matrix.copy = function(a){

	var ya = a.length;
	var xa = a[0].length;

	var m = dojo.math.matrix.create(xa, ya);

	for (var y=0; y<ya; y++){
		for (var x=0; x<xa; x++){
			m[y][x] = a[y][x];
		}
	}

	return m;
}

dojo.math.matrix.scale = function(k, a){

	a = dojo.math.matrix.copy(a);

	var ya = a.length;
	var xa = a[0].length;

	for (var y=0; y<ya; y++){
		for (var x=0; x<xa; x++){
			a[y][x] *= k;
		}
	}

	return a;
}
