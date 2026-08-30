package ysoserial.payloads;

public interface ObjectPayload<T> {
	/*
	 * return armed payload object to be serialized that will execute specified 
	 * command on deserialization
	 */
	public T getObject(String command) throws Exception;
}
