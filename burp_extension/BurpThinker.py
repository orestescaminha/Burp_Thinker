# Jython Burp extension (run under Burp's Jython env).
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.awt.event import ActionListener
from java.net import URL
from java.io import OutputStreamWriter, BufferedReader, InputStreamReader
import json
import os
import sys
from thread import start_new_thread

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

        # Inner class to handle menu actions robustly
        class MenuActionHandler(ActionListener):
            def __init__(self, extender, invocation, action):
                self.extender = extender
                self.invocation = invocation
                self.action = action
            
            def actionPerformed(self, event):
                try:
                    self.extender._callbacks.printOutput("[*] MenuActionHandler.actionPerformed called for action: %s" % self.action)
                    self.extender.send_action(self.invocation, self.action)
                except Exception as e:
                    self.extender._callbacks.printError("[!] Exception in MenuActionHandler.actionPerformed: %s" % str(e))
                    import traceback
                    self.extender._callbacks.printError(traceback.format_exc())

        # Analyze Request
        m1 = JMenuItem("Send to AI -> Analyze Request")
        m1.addActionListener(MenuActionHandler(self, invocation, "analyze_request"))
        menu.append(m1)

        # Analyze Response
        m2 = JMenuItem("Send to AI -> Analyze Response")
        m2.addActionListener(MenuActionHandler(self, invocation, "analyze_response"))
        menu.append(m2)

        # Separator can be added if desired
        # menu.append(JSeparator()) 

        # Generate XSS Payloads
        m3 = JMenuItem("Send to AI -> Generate XSS Payloads")
        m3.addActionListener(MenuActionHandler(self, invocation, "generate_xss"))
        menu.append(m3)

        # Explain CSP (only makes sense on responses)
        m4 = JMenuItem("Send to AI -> Explain CSP")
        m4.addActionListener(MenuActionHandler(self, invocation, "explain_csp"))
        menu.append(m4)

        # Explain Stack Trace
        m5 = JMenuItem("Send to AI -> Explain Stack Trace")
        m5.addActionListener(MenuActionHandler(self, invocation, "explain_stack_trace"))
        menu.append(m5)

        # Suggest Fuzzing Strategy
        m6 = JMenuItem("Send to AI -> Suggest Fuzzing Strategy")
        m6.addActionListener(MenuActionHandler(self, invocation, "suggest_fuzzing_strategy"))
        menu.append(m6)

        # Summarize Crawl
        m7 = JMenuItem("Send to AI -> Summarize Crawl")
        m7.addActionListener(MenuActionHandler(self, invocation, "summarize_crawl"))
        menu.append(m7)

        # Generate Turbo Intruder Script
        m8 = JMenuItem("Send to AI -> Generate Turbo Intruder Script")
        m8.addActionListener(MenuActionHandler(self, invocation, "generate_turbo_intruder_script"))
        menu.append(m8)
        
        return menu

    def send_action(self, invocation, action):
        """Handle context menu action selection."""
        try:
            self._callbacks.printOutput("[*] Action triggered: %s" % action)
            selected = invocation.getSelectedMessages()
            
            # For actions that need selected text (like stack trace or crawl data)
            if action in ["explain_stack_trace", "summarize_crawl"]:
                selection_bounds = invocation.getSelectionBounds()
                if selection_bounds is None:
                    self._callbacks.printError("[!] Action '%s' requires text selection." % action)
                    return
                
                http_message = selected[0] if selected else None
                if http_message:
                    raw_bytes = http_message.getRequest()
                    if not raw_bytes:
                        raw_bytes = http_message.getResponse()
                    
                    if raw_bytes:
                        raw = self._callbacks.getHelpers().bytesToString(raw_bytes[selection_bounds[0]:selection_bounds[1]])
                    else:
                        self._callbacks.printError("[!] No HTTP message found for selection.")
                        return
                else:
                    self._callbacks.printError("[!] No message selected for '%s'." % action)
                    return
            
            # For CSP, we need the response and its headers
            elif action == "explain_csp":
                http_message = selected[0]
                response_bytes = http_message.getResponse()
                if not response_bytes:
                    self._callbacks.printError("[!] Action 'Explain CSP' requires a response.")
                    return
                
                # Use Burp's helpers to parse the response and get headers
                response_info = self._callbacks.getHelpers().analyzeResponse(response_bytes)
                headers = response_info.getHeaders()
                
                csp_header = None
                for header in headers:
                    if header.lower().startswith("content-security-policy:"):
                        csp_header = header.split(":", 1)[1].strip()
                        break
                
                if not csp_header:
                    self._callbacks.printError("[!] No 'Content-Security-Policy' header found in the selected response.")
                    return
                
                # The 'raw' data for this action is just the header string
                raw = csp_header
            elif action == "suggest_fuzzing_strategy":
                if not selected:
                    self._callbacks.printError("[!] No messages selected for 'Suggest Fuzzing Strategy'.")
                    return
                http_message = selected[0]
                # Send the full request as context for fuzzing strategy
                raw = http_message.getRequest().tostring()
                if not raw:
                    self._callbacks.printError("[!] No request found for 'Suggest Fuzzing Strategy'.")
                    return
            elif action == "generate_turbo_intruder_script":
                if not selected:
                    self._callbacks.printError("[!] No messages selected for 'Generate Turbo Intruder Script'.")
                    return
                http_message = selected[0]
                raw = http_message.getRequest().tostring()
                if not raw:
                    self._callbacks.printError("[!] No request found for 'Generate Turbo Intruder Script'.")
                    return
            else:
                # For other actions, get the raw request/response bytes
                if not selected:
                    self._callbacks.printError("[!] No messages selected")
                    return
                http_message = selected[0]
                if action in ["analyze_request", "generate_xss"]:
                    msg = http_message.getRequest()
                else:
                    msg = http_message.getResponse()

                if msg is None:
                    self._callbacks.printError("[!] Request/Response is None for action: %s" % action)
                    return
                
                raw = msg.tostring()

            self._callbacks.printOutput("[*] Data length for action '%s': %d bytes" % (action, len(raw)))
            
            # Run the network request in a background thread
            start_new_thread(self._do_post, (action, raw))
            self._callbacks.printOutput("[*] Background task started for action: %s" % action)
            
        except Exception as e:
            self._callbacks.printError("[!] Error in send_action: %s" % str(e))
            import traceback
            self._callbacks.printError(traceback.format_exc())

    def _do_post(self, action, data):
        """Send data to the Burp Thinker API for analysis."""
        try:
            self._callbacks.printOutput("[*] Starting POST request...")
            
            # Determine the endpoint and body based on the action
            if action == "analyze_request":
                url_str = API_URL + "/analyze/request"
                body = json.dumps({"request": data})
            elif action == "analyze_response":
                url_str = API_URL + "/analyze/response"
                body = json.dumps({"response": data})
            elif action == "generate_xss":
                url_str = API_URL + "/payloads/xss"
                body = json.dumps({"context": data})
            elif action == "explain_csp":
                url_str = API_URL + "/explain/csp"
                body = json.dumps({"csp_header": data})
            elif action == "explain_stack_trace":
                url_str = API_URL + "/explain/stack_trace"
                body = json.dumps({"stack_trace": data})
            elif action == "suggest_fuzzing_strategy":
                url_str = API_URL + "/suggest/fuzzing_strategy"
                body = json.dumps({"context": data})
            elif action == "summarize_crawl":
                url_str = API_URL + "/summarize/crawl"
                body = json.dumps({"crawl_data": data})
            elif action == "generate_turbo_intruder_script":
                url_str = API_URL + "/generate/turbo_intruder_script"
                body = json.dumps({"base_request": data})
            else:
                self._callbacks.printError("[!] Unknown action: %s" % action)
                return

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
