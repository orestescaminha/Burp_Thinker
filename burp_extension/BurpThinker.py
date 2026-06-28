# Jython Burp extension (run under Burp's Jython env).
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.lang import Runnable, Thread
from java.net import URL
from java.io import OutputStreamWriter, BufferedReader, InputStreamReader
import json
import os
import sys

# Read token from environment or use default
API_URL = "http://127.0.0.1:8000"
TOKEN = os.environ.get("BURP_THINKER_TOKEN", "local-secret")

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        """Required by Burp Suite API to register the extension."""
        self._callbacks = callbacks
        callbacks.setExtensionName("Burp Thinker")
        callbacks.registerContextMenuFactory(self)
        callbacks.printOutput("[*] Burp Thinker extension loaded successfully")
        callbacks.printOutput("[*] API URL: %s" % API_URL)
        callbacks.printOutput("[*] Token: %s" % ("***" if TOKEN else "NOT SET"))

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
        try:
            self._callbacks.printOutput("[*] Action triggered: %s" % action)
            selected = invocation.getSelectedMessages()
            if selected is None or len(selected) == 0:
                self._callbacks.printError("[!] No messages selected")
                return
            self._callbacks.printOutput("[*] Selected %d message(s)" % len(selected))
            
            msg = selected[0].getRequest() if action=="analyze_request" else selected[0].getResponse()
            if msg is None:
                self._callbacks.printError("[!] Request/Response is None")
                return
            
            raw = msg.tostring()
            self._callbacks.printOutput("[*] Raw message length: %d bytes" % len(raw))
            
            # Run in background thread
            t = Thread(Runnable(lambda: self._do_post(action, raw)))
            t.start()
            self._callbacks.printOutput("[*] Background thread started for analysis")
        except Exception as e:
            self._callbacks.printError("[!] Error in send_action: %s" % str(e))
            import traceback
            self._callbacks.printError(traceback.format_exc())

    def _do_post(self, action, raw):
        """Send HTTP request/response to Burp Thinker API for analysis."""
        try:
            self._callbacks.printOutput("[*] Starting POST request...")
            url_str = API_URL + ("/analyze/request" if action=="analyze_request" else "/analyze/response")
            self._callbacks.printOutput("[*] URL: %s" % url_str)
            
            url = URL(url_str)
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setDoOutput(True)
            conn.setConnectTimeout(10000)  # 10 seconds
            conn.setReadTimeout(30000)     # 30 seconds
            
            # Set headers
            conn.setRequestProperty("Authorization", "Bearer " + TOKEN)
            conn.setRequestProperty("Content-Type", "application/json")
            self._callbacks.printOutput("[*] Headers set")
            
            # Prepare body
            if action=="analyze_request":
                body = json.dumps({"request": raw})
            else:
                body = json.dumps({"response": raw})
            self._callbacks.printOutput("[*] Body prepared, size: %d bytes" % len(body))
            
            # Write to connection
            w = OutputStreamWriter(conn.getOutputStream(), "utf-8")
            w.write(body)
            w.flush()
            w.close()
            self._callbacks.printOutput("[*] Body sent")
            
            # Read response
            rcode = conn.getResponseCode()
            self._callbacks.printOutput("[*] Response code: %d" % rcode)
            
            # Read response body
            try:
                in_stream = BufferedReader(InputStreamReader(conn.getInputStream(), "utf-8"))
            except Exception as e:
                # Try error stream if input stream fails
                self._callbacks.printError("[!] Failed to get input stream: %s" % str(e))
                in_stream = BufferedReader(InputStreamReader(conn.getErrorStream(), "utf-8"))
            
            sb = []
            line = in_stream.readLine()
            while line is not None:
                sb.append(line)
                line = in_stream.readLine()
            in_stream.close()
            
            response_text = "".join(sb)
            self._callbacks.printOutput("[+] Burp Thinker result (HTTP %d):\n%s" % (rcode, response_text))
            
        except Exception as e:
            self._callbacks.printError("[!] Burp Thinker error: %s" % str(e))
            import traceback
            self._callbacks.printError(traceback.format_exc())
