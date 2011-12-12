package msfgui;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * XMLRPC implementation of an RpcConnection.
 *
 * Implements a minimal XMLRPC client for our purposes. Reinventing the wheel is
 * usually a bad idea, but CVE/description searching takes a long time and this
 * implementation runs a CVE search twice as fast as the apache libs. It also
 * results in a more responsive console.
 *
 * @author scriptjunkie
 */
public class XmlRpc extends RpcConnection {

	/**
	 * We're an XML RPC
	 */
	public XmlRpc(){
		super();
	}
	/** Creates an XMLRPC call from the given method name and parameters and sends it */
	protected void writeCall(String methname, Object[] params) throws Exception{
		if(methname.endsWith("write"))
			params[2] = Base64.encode(params[2].toString().getBytes());
		if(methname.startsWith("db.import_"))
			((Map)params[1]).put("data", Base64.encode((byte[])((Map)params[1]).get("data")));
		if(methname.equals("module.encode"))
			params[1] = Base64.encode((byte[])params[1]);
		Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
		Element methodCall = doc.createElement("methodCall");
		doc.appendChild(methodCall);
		Element methodName = doc.createElement("methodName");
		methodName.appendChild(doc.createTextNode(methname));
		methodCall.appendChild(methodName);
		Element paramsEl = doc.createElement("params");
		methodCall.appendChild(paramsEl);
		//Add each parameter by type. Usually just the maps are difficult
		for(Object param : params){
			Element paramEl = doc.createElement("param");
			paramEl.appendChild(objectToNode(doc,param));
			paramsEl.appendChild(paramEl);
		}
		ByteArrayOutputStream bout = new  ByteArrayOutputStream();
		TransformerFactory.newInstance().newTransformer().transform(new DOMSource(doc), new StreamResult(bout));
		sout.write(bout.toByteArray());
		sout.write(0);
	}

	/**
	 * Takes the object provided and recursively creates a node out of it suitable
	 * for xmlrpc transmission.
	 * @param doc
	 * @param param
	 * @return
	 */
	public static Node objectToNode(Document doc, Object param){
		Node valEl = doc.createElement("value");
		if(param instanceof Map){ //Reverse of the parseVal() struct-to-HashMap code
			Element structEl = doc.createElement("struct");
			for(Object entryObj : ((Map)param).entrySet()){
				Map.Entry ent = (Map.Entry)entryObj;
				Element membEl = doc.createElement("member");
				Element nameEl = doc.createElement("name");
				nameEl.appendChild(doc.createTextNode(ent.getKey().toString()));
				membEl.appendChild(nameEl);
				membEl.appendChild(objectToNode(doc,ent.getValue()));
				structEl.appendChild(membEl);
			}
			valEl.appendChild(structEl);
		}else if(param instanceof List || param instanceof Object[]){ //Reverse of the parseVal() array-to-HashMap code
			Element arrayEl = doc.createElement("array");
			Element dataEl = doc.createElement("data");
			if(param instanceof Object[])
				for(Object obj : (Object[])param)
					dataEl.appendChild(objectToNode(doc,obj));
			else
				for(Object obj : (List)param)
					dataEl.appendChild(objectToNode(doc,obj));
			arrayEl.appendChild(dataEl);
			valEl.appendChild(arrayEl);
		}else if(param instanceof Integer){ //not sure I even need this
			Element i4El = doc.createElement("i4");
			i4El.appendChild(doc.createTextNode(param.toString()));
			valEl.appendChild(i4El);
		}else if(param instanceof Boolean){ //not sure I even need this
			Element boolEl = doc.createElement("boolean");
			boolEl.appendChild(doc.createTextNode(param.toString()));
			valEl.appendChild(boolEl);
		}else{
			Element strEl = doc.createElement("string");
			strEl.appendChild(doc.createTextNode(param.toString()));
			valEl.appendChild(strEl);
		}
		return valEl;
	}

	/** Receives an XMLRPC response and converts to an object */
	protected Object readResp() throws Exception{
		//Will store our response
		StringBuilder sb = new StringBuilder();
		int len;
		do{
			//read bytes
			ByteArrayOutputStream cache = new ByteArrayOutputStream();
			int val;
			while((val = sin.read()) != 0){
				if(val == -1)
					throw new MsfException("Stream died.");
				cache.write(val);
			}
			//parse the response: <methodResponse><params><param><value>...
			ByteArrayInputStream is = new ByteArrayInputStream(cache.toByteArray());
			int a = is.read();
			while(a != -1){
				if(!Character.isISOControl(a) || a == '\t')
					sb.append((char)a);
				//else
				//	sb.append("&#x").append(Integer.toHexString(a)).append(';');
				a = is.read();
			}
			len = sb.length();//Check to make sure we aren't stopping on an embedded null
		} while (sb.lastIndexOf("</methodResponse>") < len - 20 || len < 30);
		Document root = DocumentBuilderFactory.newInstance().newDocumentBuilder()
				.parse(new ByteArrayInputStream(sb.toString().getBytes()));

		if(!root.getFirstChild().getNodeName().equals("methodResponse"))
			throw new MsfException("Error reading response: not a response.");
		Node methResp = root.getFirstChild();
		if(methResp.getFirstChild().getNodeName().equals("fault")){
			throw new MsfException(methResp.getFirstChild()//fault
					.getFirstChild() // value
					.getFirstChild() // struct
					.getLastChild() // member
					.getLastChild() // value
					.getTextContent());
		}
		Node params = methResp.getFirstChild();
		if(!params.getNodeName().equals("params"))
			throw new MsfException("Error reading response: no params.");
		Node param = params.getFirstChild();
		if(!param.getNodeName().equals("param"))
			throw new MsfException("Error reading response: no param.");
		Node value = param.getFirstChild();
		if(!value.getNodeName().equals("value"))
			throw new MsfException("Error reading response: no value.");
		return parseVal(value);
	}

	/** Takes an XMLRPC DOM value node and creates a java object out of it recursively */
	public static Object parseVal(Node submemb) throws MsfException {
		Node type = submemb.getFirstChild();
		String typeName = type.getNodeName();
		if(typeName.equals("string")){//<struct><member><name>jobs</name><value><struct/></value></member></struct>
			return type.getTextContent(); //String returns java string
		}else if (typeName.equals("array")){ //Array returns List
			ArrayList arrgh = new ArrayList();
			Node data = type.getFirstChild();
			if(!data.getNodeName().equals("data"))
				throw new MsfException("Error reading array: no data.");
			for(Node val = data.getFirstChild(); val != null; val = val.getNextSibling())
				arrgh.add(parseVal(val));
			return arrgh;
		}else if (typeName.equals("struct")){ //Struct returns a HashMap of name->value member pairs
			HashMap structmembs = new HashMap();
			for(Node member = type.getFirstChild(); member != null; member = member.getNextSibling()){
				if(!member.getNodeName().equals("member"))
					throw new MsfException("Error reading response: non struct member.");
				Object name = null, membValue = null;
				//get each member and put into output map
				for(Node submember = member.getFirstChild(); submember != null; submember = submember.getNextSibling()){
					if(submember.getNodeName().equals("name"))
						name = submember.getTextContent();
					else if (submember.getNodeName().equals("value"))
						membValue = parseVal(submember); //Value can be arbitrarily complex
				}
				structmembs.put(name, membValue);
			}
			return structmembs;
		}else if (typeName.equals("i4")){
			return new Integer(type.getTextContent());
		}else if (typeName.equals("boolean")){
			return type.getTextContent().equals("1") || Boolean.valueOf(type.getTextContent());
		}else if (typeName.equals("dateTime.iso8601")) {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd'T'HH:mm:ss");
			try{
				return sdf.parse(type.getTextContent());
			}catch(ParseException pex){
				return type.getTextContent();
			}
		} else {
			throw new MsfException("Error reading val: unknown type " + typeName);
		}
	}
}
