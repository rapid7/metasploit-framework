/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.html.SortableTable");
dojo.require("dojo.lang");
dojo.require("dojo.date");
dojo.require("dojo.html");
dojo.require("dojo.event.*");
dojo.require("dojo.widget.HtmlWidget");
dojo.require("dojo.widget.SortableTable");

dojo.widget.html.SortableTable=function(){
	//	summary
	//	Constructor for the SortableTable widget
	dojo.widget.SortableTable.call(this);
	dojo.widget.HtmlWidget.call(this);

	this.headClass="";
	this.tbodyClass="";
	this.headerClass="";
	this.headerSortUpClass="selected";
	this.headerSortDownClass="selected";
	this.rowClass="";
	this.rowAlternateClass="alt";
	this.rowSelectedClass="selected";
	this.columnSelected="sorted-column";
};
dojo.inherits(dojo.widget.html.SortableTable, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.html.SortableTable, {
	templatePath:null,
	templateCssPath:null,

	getTypeFromString:function(/* string */ s){
		//	summary
		//	Find the constructor that matches param s by searching through the entire object tree.
		var parts=s.split("."),i=0,obj=dj_global; 
		do{obj=obj[parts[i++]];}while(i<parts.length&&obj); 
		return(obj!=dj_global)?obj:null;	//	function
	},
	compare:function(/* object */ o1, /* object */ o2){
		//	summary
		//	Compare two objects using a shallow property compare
		for(var p in o1){
			if(!(p in o2)) return false;	//	boolean
			if(o1[p].valueOf()!=o2[p].valueOf()) return false;	//	boolean
		}
		return true;	// boolean
	},
	isSelected:function(/* object */ o){
		//	summary
		//	checked to see if the passed object is in the current selection.
		for(var i=0;i<this.selected.length;i++){
			if(this.compare(this.selected[i],o)){
				return true; // boolean
			}
		}
		return false;	// boolean
	},
	removeFromSelected:function(/* object */ o){
		//	summary
		//	remove the passed object from the current selection.
		var idx=-1;
		for(var i=0;i<this.selected.length;i++){
			if(this.compare(this.selected[i],o)){
				idx=i;
				break;
			}
		}
		if(idx>=0){
			this.selected.splice(idx,1);
		}
	},
	getSelection:function(){
		//	summary
		//	return the array of currently selected objects (JSON format)
		return this.selected;	//	array
	},
	getValue:function(){
		//	summary
		//	return a comma-delimited list of selected valueFields.
		var a=[];
		for(var i=0;i<this.selected.length;i++){
			if (this.selected[i][this.valueField]){
				a.push(this.selected[i][this.valueField]);
			}
		}
		return a.join();	//	string
	},
	reset:function(){
		//	summary
		//	completely resets the internal representations.
		this.columns=[];
		this.data=[];
		this.resetSelections(this.domNode.getElementsByTagName("tbody")[0]);
	},
	resetSelections:function(/* HTMLTableBodyElement */ body){
		this.selected=[];
		var idx=0;
		var rows=body.getElementsByTagName("tr");
		for(var i=0; i<rows.length; i++){
			if(rows[i].parentNode==body){
				rows[i].removeAttribute("selected");
				if(this.enableAlternateRows&&idx%2==1){
					rows[i].className=this.rowAlternateClass;
				}else{
					rows[i].className="";
				}
				idx++;
			}
		}
	},

	getObjectFromRow:function(/* HTMLTableRowElement */ row){
		//	summary
		//	creates a JSON object based on the passed row
		var cells=row.getElementsByTagName("td");
		var o={};
		for(var i=0; i<this.columns.length;i++){
			if(this.columns[i].sortType=="__markup__"){
				//	FIXME: should we parse this instead?  Because if the user may not get back the markup they put in...
				o[this.columns[i].getField()]=cells[i].innerHTML;
			}else{
				var text=dojo.html.renderedTextContent(cells[i]);
				var val=new (this.columns[i].getType())(text);
				o[this.columns[i].getField()]=val;
			}
		}
		if(dojo.html.hasAttribute(row,"value")){
			o[this.valueField]=dojo.html.getAttribute(row,"value");
		}
		return o;	//	object
	},
	setSelectionByRow:function(/* HTMLTableElementRow */ row){
		//	summary
		//	create the selection object based on the passed row, makes sure it's unique.
		//	note that you need to call render manually (because of multi-select operations)
		var o=this.getObjectFromRow(row);
		var b=false;
		for(var i=0;i<this.selected.length;i++){
			if(this.compare(this.selected[i], o)){
				b=true;
				break;
			}
		}
		if(!b){
			this.selected.push(o);
		}
	},

	parseColumns:function(/* HTMLTableHeadElement */ node){
		//	summary
		//	parses the passed element to create column objects
		this.reset();
		var row=node.getElementsByTagName("tr")[0];
		var cells=row.getElementsByTagName("td");
		if (cells.length==0) cells=row.getElementsByTagName("th");
		for(var i=0; i<cells.length; i++){
			var o={
				field:null,
				format:null,
				noSort:false,
				sortType:"String",
				dataType:String,
				sortFunction:null,
				label:null,
				align:"left",
				valign:"middle",
				getField:function(){ return this.field||this.label; },
				getType:function(){ return this.dataType; }
			};
			//	presentation attributes
			if(dojo.html.hasAttribute(cells[i], "align")){
				o.align=dojo.html.getAttribute(cells[i],"align");
			}
			if(dojo.html.hasAttribute(cells[i], "valign")){
				o.valign=dojo.html.getAttribute(cells[i],"valign");
			}

			//	sorting features.
			if(dojo.html.hasAttribute(cells[i], "nosort")){
				o.noSort=dojo.html.getAttribute(cells[i],"nosort")=="true";
			}
			if(dojo.html.hasAttribute(cells[i], "sortusing")){
				var trans=dojo.html.getAttribute(cells[i],"sortusing");
				var f=this.getTypeFromString(trans);
				if (f!=null && f!=window && typeof(f)=="function") 
					o.sortFunction=f;
			}

			if(dojo.html.hasAttribute(cells[i], "field")){
				o.field=dojo.html.getAttribute(cells[i],"field");
			}
			if(dojo.html.hasAttribute(cells[i], "format")){
				o.format=dojo.html.getAttribute(cells[i],"format");
			}
			if(dojo.html.hasAttribute(cells[i], "dataType")){
				var sortType=dojo.html.getAttribute(cells[i],"dataType");
				if(sortType.toLowerCase()=="html"||sortType.toLowerCase()=="markup"){
					o.sortType="__markup__";	//	always convert to "__markup__"
					o.noSort=true;
				}else{
					var type=this.getTypeFromString(sortType);
					if(type){
						o.sortType=sortType;
						o.dataType=type;
					}
				}
			}
			o.label=dojo.html.renderedTextContent(cells[i]);
			this.columns.push(o);

			//	check to see if there's a default sort, and set the properties necessary
			if(dojo.html.hasAttribute(cells[i], "sort")){
				this.sortIndex=i;
				var dir=dojo.html.getAttribute(cells[i], "sort");
				if(!isNaN(parseInt(dir))){
					dir=parseInt(dir);
					this.sortDirection=(dir!=0)?1:0;
				}else{
					this.sortDirection=(dir.toLowerCase()=="desc")?1:0;
				}
			}
		}
	},

	parseData:function(/* array */ data){
		//	summary
		//	Parse the passed JSON data structure, and cast based on columns.
		this.data=[];
		this.selected=[];
		for(var i=0; i<data.length; i++){
			var o={};	//	new data object.
			for(var j=0; j<this.columns.length; j++){
				var field=this.columns[j].getField();
				if(this.columns[j].sortType=="__markup__"){
					o[field]=String(data[i][field]);
				}else{
					var type=this.columns[j].getType();
					var val=data[i][field];
					var t=this.columns[j].sortType.toLowerCase();
					if(val){
						o[field]=new type(val);
					}else{
						o[field]=new type();	//	let it use the default.
					}
				}
			}
			//	check for the valueField if not already parsed.
			if(data[i][this.valueField]&&!o[this.valueField]){
				o[this.valueField]=data[i][this.valueField];
			}
			this.data.push(o);
		}
	}, 

	parseDataFromTable:function(/* HTMLTableBodyElement */ tbody){
		//	summary
		//	parses the data in the tbody of a table to create a set of objects.
		//	Will add objects to this.selected if an attribute 'selected="true"' is present on the row.
		this.data=[];
		this.selected=[];
		var rows=tbody.getElementsByTagName("tr");
		for(var i=0; i<rows.length; i++){
			if(dojo.html.getAttribute(rows[i],"ignoreIfParsed")=="true"){
				continue;
			}
			var o={};	//	new data object.
			var cells=rows[i].getElementsByTagName("td");
			for(var j=0; j<this.columns.length; j++){
				var field=this.columns[j].getField();
				if(this.columns[j].sortType=="__markup__"){
					//	FIXME: parse this?
					o[field]=cells[j].innerHTML;
				}else{
					var type=this.columns[j].getType();
					var val=dojo.html.renderedTextContent(cells[j]); //	should be the same index as the column.
					if (val) o[field]=new type(val);
					else o[field]=new type();	//	let it use the default.
				}
			}
			if(dojo.html.hasAttribute(rows[i],"value")&&!o[this.valueField]){
				o[this.valueField]=dojo.html.getAttribute(rows[i],"value");
			}
			//	FIXME: add code to preserve row attributes in __metadata__ field?
			this.data.push(o);
			
			//	add it to the selections if selected="true" is present.
			if(dojo.html.getAttribute(rows[i],"selected")=="true"){
				this.selected.push(o);
			}
		}
	},
	
	showSelections:function(){
		var body=this.domNode.getElementsByTagName("tbody")[0];
		var rows=body.getElementsByTagName("tr");
		var idx=0;
		for(var i=0; i<rows.length; i++){
			if(rows[i].parentNode==body){
				if(dojo.html.getAttribute(rows[i],"selected")=="true"){
					rows[i].className=this.rowSelectedClass;
				} else {
					if(this.enableAlternateRows&&idx%2==1){
						rows[i].className=this.rowAlternateClass;
					}else{
						rows[i].className="";
					}
				}
				idx++;
			}
		}
	},
	render:function(bDontPreserve){
		//	summary
		//	renders the table to the browser
		var data=[];
		var body=this.domNode.getElementsByTagName("tbody")[0];

		if(!bDontPreserve){
			//	rebuild data and selection
			this.parseDataFromTable(body);
		}

		//	clone this.data for sorting purposes.
		for(var i=0; i<this.data.length; i++){
			data.push(this.data[i]);
		}
		
		var col=this.columns[this.sortIndex];
		if(!col.noSort){
			var field=col.getField();
			if(col.sortFunction){
				var sort=col.sortFunction;
			}else{
				var sort=function(a,b){
					if (a[field]>b[field]) return 1;
					if (a[field]<b[field]) return -1;
					return 0;
				}
			}
			data.sort(sort);
			if(this.sortDirection!=0) data.reverse();
		}

		//	build the table and pop it in.
		while(body.childNodes.length>0) body.removeChild(body.childNodes[0]);
		for(var i=0; i<data.length;i++){
			var row=document.createElement("tr");
			dojo.html.disableSelection(row);
			if (data[i][this.valueField]){
				row.setAttribute("value",data[i][this.valueField]);
			}
			if(this.isSelected(data[i])){
				row.className=this.rowSelectedClass;
				row.setAttribute("selected","true");
			} else {
				if(this.enableAlternateRows&&i%2==1){
					row.className=this.rowAlternateClass;
				}
			}
			for(var j=0;j<this.columns.length;j++){
				var cell=document.createElement("td");
				cell.setAttribute("align", this.columns[j].align);
				cell.setAttribute("valign", this.columns[j].valign);
				dojo.html.disableSelection(cell);
				if(this.sortIndex==j){
					cell.className=this.columnSelected;
				}
				if(this.columns[j].sortType=="__markup__"){
					cell.innerHTML=data[i][this.columns[j].getField()];
					for(var k=0; k<cell.childNodes.length; k++){
						var node=cell.childNodes[k];
						if(node&&node.nodeType==dojo.html.ELEMENT_NODE){
							dojo.html.disableSelection(node);
						}
					}
				}else{
					if(this.columns[j].getType()==Date){
						var format=this.defaultDateFormat;
						if(this.columns[j].format) format=this.columns[j].format;
						cell.appendChild(document.createTextNode(dojo.date.format(data[i][this.columns[j].getField()], format)));
					}else{
						cell.appendChild(document.createTextNode(data[i][this.columns[j].getField()]));
					}
				}
				row.appendChild(cell);
			}
			body.appendChild(row);
			dojo.event.connect(row, "onclick", this, "onUISelect");
		}
		
		//	if minRows exist.
		var minRows=parseInt(this.minRows);
		if (!isNaN(minRows) && minRows>0 && data.length<minRows){
			var mod=0;
			if(data.length%2==0) mod=1;
			var nRows=minRows-data.length;
			for(var i=0; i<nRows; i++){
				var row=document.createElement("tr");
				row.setAttribute("ignoreIfParsed","true");
				if(this.enableAlternateRows&&i%2==mod){
					row.className=this.rowAlternateClass;
				}
				for(var j=0;j<this.columns.length;j++){
					var cell=document.createElement("td");
					cell.appendChild(document.createTextNode("\u00A0"));
					row.appendChild(cell);
				}
				body.appendChild(row);
			}
		}
	},

	//	the following the user can override.
	onSelect:function(/* DomEvent */ e){ 
		//	summary
		//	empty function for the user to attach code to, fired by onUISelect
	},
	onUISelect:function(/* DomEvent */ e){
		//	summary
		//	fired when a user selects a row
		var row=dojo.html.getParentByType(e.target,"tr");
		var body=dojo.html.getParentByType(row,"tbody");
		if(this.enableMultipleSelect){
			if(e.metaKey||e.ctrlKey){
				if(this.isSelected(this.getObjectFromRow(row))){
					this.removeFromSelected(this.getObjectFromRow(row));
					row.removeAttribute("selected");
				}else{
					//	push onto the selection stack.
					this.setSelectionByRow(row);
					row.setAttribute("selected","true");
				}
			}else if(e.shiftKey){
				//	the tricky one.  We need to figure out the *last* selected row above, 
				//	and select all the rows in between.
				var startRow;
				var rows=body.getElementsByTagName("tr");
				//	if there's a selection above, we go with that first. 
				for(var i=0;i<rows.length;i++){
					if(rows[i].parentNode==body){
						if(rows[i]==row) break;
						if(dojo.html.getAttribute(rows[i],"selected")=="true"){
							startRow=rows[i];
						}
					}
				}
				//	if there isn't a selection above, we continue with a selection below.
				if(!startRow){
					startRow=row;
					for(;i<rows.length;i++){
						if(dojo.html.getAttribute(rows[i],"selected")=="true"){
							row=rows[i];
							break;
						}
					}
				}
				this.resetSelections(body);
				if(startRow==row){
					//	this is the only selection
					row.setAttribute("selected","true");
					this.setSelectionByRow(row);
				}else{
					var doSelect=false;
					for(var i=0; i<rows.length; i++){
						if(rows[i].parentNode==body){
							rows[i].removeAttribute("selected");
							if(rows[i]==startRow){
								doSelect=true;
							}
							if(doSelect){
								this.setSelectionByRow(rows[i]);
								rows[i].setAttribute("selected","true");
							}
							if(rows[i]==row){
								doSelect=false;
							}
						}
					}
				}
			}else{
				//	reset the selection
				this.resetSelections(body);
				row.setAttribute("selected","true");
				this.setSelectionByRow(row);
			}
		}else{
			//	reset the data selection and go.
			this.resetSelections(body);
			row.setAttribute("selected","true");
			this.setSelectionByRow(row);
		}
		this.showSelections();
		this.onSelect(e);
		e.stopPropagation();
		e.preventDefault();
	},
	onHeaderClick:function(/* DomEvent */ e){
		//	summary
		//	Main handler function for each header column click.
		var oldIndex=this.sortIndex;
		var oldDirection=this.sortDirection;
		var source=e.target;
		var row=dojo.html.getParentByType(source,"tr");
		var cellTag="td";
		if(row.getElementsByTagName(cellTag).length==0) cellTag="th";

		var headers=row.getElementsByTagName(cellTag);
		var header=dojo.html.getParentByType(source,cellTag);
		
		for(var i=0; i<headers.length; i++){
			if(headers[i]==header){
				if(i!=oldIndex){
					//	new col.
					this.sortIndex=i;
					this.sortDirection=0;
					headers[i].className=this.headerSortDownClass
				}else{
					this.sortDirection=(oldDirection==0)?1:0;
					if(this.sortDirection==0){
						headers[i].className=this.headerSortDownClass;
					}else{
						headers[i].className=this.headerSortUpClass;
					}
				}
			}else{
				//	reset the header class.
				headers[i].className=this.headerClass;
			}
		}
		this.render();
	},

	postCreate:function(){ 
		// 	summary
		//	overridden from HtmlWidget, initializes and renders the widget.
		var thead=this.domNode.getElementsByTagName("thead")[0];
		if(this.headClass.length>0){
			thead.className=this.headClass;
		}

		//	disable selections
		dojo.html.disableSelection(this.domNode);

		//	parse the columns.
		this.parseColumns(thead);

		//	attach header handlers.
		var header="td";
		if(thead.getElementsByTagName(header).length==0) header="th";
		var headers=thead.getElementsByTagName(header);
		for(var i=0; i<headers.length; i++){
			if(!this.columns[i].noSort){
				dojo.event.connect(headers[i], "onclick", this, "onHeaderClick");
			}
			if(this.sortIndex==i){
				if(this.sortDirection==0){
					headers[i].className=this.headerSortDownClass;
				}else{
					headers[i].className=this.headerSortUpClass;
				}
			}
		}

		//	parse the tbody element and re-render it.
		var tbody=this.domNode.getElementsByTagName("tbody")[0];
		if (this.tbodyClass.length>0) {
			tbody.className=this.tbodyClass;
		}

		this.parseDataFromTable(tbody);
		this.render(true);
	}
});
