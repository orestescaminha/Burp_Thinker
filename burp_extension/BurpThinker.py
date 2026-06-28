# Jython Burp extension (run under Burp's Jython env).
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.lang import Runnable, Thread
from java.net import URL
from java.io import OutputStreamWriter, BufferedReader, InputStreamReader
import json

API_URL = "http://127.0.0.1:8000"
TOKEN = "local-secret"  # Burp extension never stores provider keys; this is local API token

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        """Required by Burp Suite API to register the extension."""
        self._callbacks = callbacks
        callbacks.setExtensionName("Burp Thinker")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        """Create context menu items for Burp Thinker actions."""
        menu = []
        m1 = JMenuItem("Send to AI -> Analyze Request", actionPerformed=lambda ev, inv=invocation: self.send_action(inv, "analyze_request"))
        m2 = JMenuItem("Send to AI -> Analyze Response", actionPerformed=lambda ev, inv=invocation: self.send_action(inv, "analyze_response"))
        menu.append(m1)
        menu.append(m2)
        return menu

    def send_action(self, invocation, action):
        """Handle context menu action selection."""
        selected = invocation.getSelectedMessages()
        if selected is None or len(selected) == 0:
            return
        msg = selected[0].getRequest() if action=="analyze_request" else selected[0].getResponse()
        raw = msg.tostring()
        t = Thread(Runnable(lambda: self._do_post(action, raw)))
        t.start()

    def _do_post(self, action, raw):
        """Send HTTP request/response to Burp Thinker API for analysis."""
        try:
            url = URL(API_URL + ("/analyze/request" if action=="analyze_request" else "/analyze/response"))
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setDoOutput(True)
            conn.setRequestProperty("Authorization", "Bearer " + TOKEN)
            conn.setRequestProperty("Content-Type", "application/json")
            body = json.dumps({"request": raw}) if action=="analyze_request" else json.dumps({"response": raw})
            w = OutputStreamWriter(conn.getOutputStream(), "utf-8")
            w.write(body)
            w.flush()
            w.close()
            rcode = conn.getResponseCode()
            in_stream = BufferedReader(InputStreamReader(conn.getInputStream(), "utf-8"))
            sb = []
            line = in_stream.readLine()
            while line is not None:
                sb.append(line)
                line = in_stream.readLine()
            in_stream.close()
            self._callbacks.printOutput("Burp Thinker result (HTTP %s): %s" % (rcode, "".join(sb)))
        except Exception as e:
            self._callbacks.printError("Burp Thinker error: %s" % e)
