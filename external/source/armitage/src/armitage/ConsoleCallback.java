package armitage;

public interface ConsoleCallback {
	public void sessionRead(String sessionid, String text);
	public void sessionWrote(String sessionid, String text);
}
