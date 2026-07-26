# Jython Burp extension (run under Burp's Jython env).
from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import JMenuItem, JSplitPane, JScrollPane, JTable, JPanel, JButton, JTextPane
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout
from java.awt.event import ActionListener
from java.net import URL
from java.io import OutputStreamWriter, BufferedReader, InputStreamReader
import json
import os
import sys
from thread import start_new_thread
from javax.swing import SwingUtilities

# --- Configuration ---
API_URL = "http://127.0.0.1:8000"
TOKEN = os.environ.get("BURP_THINKER_TOKEN", "local-secret")

# --- UI Class for the new Tab ---
class BurpThinkerTab(ITab):
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.history_data = []

        # Create the main UI panel
        self._main_panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # Top panel for history table
        history_panel = JPanel(BorderLayout())
        column_names = ["#", "Action", "Target"]
        self.history_model = DefaultTableModel(column_names, 0)
        self.history_table = JTable(self.history_model)
        history_scroll_pane = JScrollPane(self.history_table)
        history_panel.add(history_scroll_pane, BorderLayout.CENTER)

        # Bottom panel for detailed results
        result_panel = JPanel(BorderLayout())
        self.result_pane = JTextPane()
        self.result_pane.setContentType("text/html")
        self.result_pane.setEditable(False)
        result_scroll_pane = JScrollPane(self.result_pane)
        result_panel.add(result_scroll_pane, BorderLayout.CENTER)
        
        # Add a "Clear History" button
        clear_button = JButton("Clear History", actionPerformed=self.clear_history)
        button_panel = JPanel()
        button_panel.add(clear_button)
        history_panel.add(button_panel, BorderLayout.SOUTH)

        self._main_panel.setTopComponent(history_panel)
        self._main_panel.setBottomComponent(result_panel)
        self._main_panel.setResizeWeight(0.4) # Give 40% of space to the top panel initially

        # Add a listener to the history table to show details on selection
        self.history_table.getSelectionModel().addListSelectionListener(self.on_history_selection)

    def getTabCaption(self):
        return "Burp Thinker"

    def getUiComponent(self):
        return self._main_panel

    def add_analysis_result(self, action, target, result_json):
        # This method will be called from the main extension thread
        # Use SwingUtilities to ensure UI updates happen on the Event Dispatch Thread (EDT)
        def update_ui():
            self.history_data.append(result_json)
            row_index = len(self.history_data)
            self.history_model.addRow([row_index, action, target])
        
        SwingUtilities.invokeLater(update_ui)

    def on_history_selection(self, event):
        if event.getValueIsAdjusting():
            return
        
        try:
            selected_row = self.history_table.getSelectedRow()
            self._callbacks.printOutput("[UI DEBUG] Row selected: %d" % selected_row)

            if selected_row == -1:
                self.result_pane.setText("")
                return
            
            result_data = self.history_data[selected_row]
            self._callbacks.printOutput("[UI DEBUG] Data for row: " + json.dumps(result_data))

            html_content = self._format_json_to_html(result_data)
            self._callbacks.printOutput("[UI DEBUG] Generated HTML (first 100 chars): " + html_content[:100])
            
            self.result_pane.setText(html_content)
            self.result_pane.setCaretPosition(0)
        except Exception as e:
            self._callbacks.printError("[UI ERROR] Failed in on_history_selection: %s" % str(e))
            import traceback
            self._callbacks.printError(traceback.format_exc())

    def _format_json_to_html(self, data):
        """Converts a JSON analysis object into a nicely formatted HTML string."""
        try:
            if not isinstance(data, dict):
                return "<html><pre>" + str(data) + "</pre></html>"

            # Basic CSS for styling
            style = """
            <style>
                body { font-family: sans-serif; margin: 5px; }
                h2 { color: #FF6633; border-bottom: 1px solid #FF6633; padding-bottom: 2px; margin-top: 15px;}
                h3 { color: #333; margin-top: 10px; }
                ul { list-style-type: disc; margin-left: 20px; }
                li { margin-bottom: 5px; }
                code { background-color: #f0f0f0; padding: 2px 4px; border-radius: 3px; }
                pre { background-color: #f0f0f0; padding: 10px; border: 1px solid #ccc; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; }
            </style>
            """
            
            html = ["<html><head>", style, "</head><body>"]
            
            # Handle specific schemas or fallback to generic display
            if "script_code" in data: # Turbo Intruder Script
                html.append("<h2>Generated Script</h2><pre><code>" + data.get("script_code", "").replace("<", "&lt;") + "</code></pre>")
                html.append("<h2>Explanation</h2><p>" + data.get("explanation", "") + "</p>")
                if data.get("suggested_payloads"):
                    html.append("<h2>Suggested Payloads</h2><ul>")
                    for item in data["suggested_payloads"]:
                        html.append("<li><code>" + item.replace("<", "&lt;") + "</code></li>")
                    html.append("</ul>")
            
            elif "payloads" in data: # Generic payload list
                 html.append("<h2>Generated Payloads</h2><ul>")
                 for item in data["payloads"]:
                    html.append("<li><code>" + item.replace("<", "&lt;") + "</code></li>")
                 html.append("</ul>")

            else: # Generic analysis format
                for key, value in data.items():
                    title = key.replace("_", " ").title()
                    html.append("<h2>" + title + "</h2>")
                    
                    if isinstance(value, list) and value:
                        html.append("<ul>")
                        for item in value:
                            html.append("<li>" + str(item).replace("<", "&lt;") + "</li>")
                        html.append("</ul>")
                    elif isinstance(value, dict) and value:
                        html.append("<ul>")
                        for k, v in value.items():
                            html.append("<li><strong>" + k + ":</strong> " + str(v).replace("<", "&lt;") + "</li>")
                        html.append("</ul>")
                    elif isinstance(value, str) and value:
                        if "def " in value or "import " in value:
                             html.append("<pre><code>" + value.replace("<", "&lt;") + "</code></pre>")
                        else:
                            html.append("<p>" + value + "</p>")
                    elif value: # Handle other types like numbers
                        html.append("<p>" + str(value) + "</p>")
                    else:
                        html.append("<p>N/A</p>")

            html.append("</body></html>")
            return "".join(html)
        except Exception as e:
            self._callbacks.printError("[UI ERROR] Failed in _format_json_to_html: %s" % str(e))
            import traceback
            self._callbacks.printError(traceback.format_exc())
            return "<html><body><h2>Error rendering HTML</h2><p>Check the Burp Extender error console for details.</p></body></html>"

    def clear_history(self, event):
        def do_clear():
            self.history_data = []
            # Clear the table model
            while self.history_model.getRowCount() > 0:
                self.history_model.removeRow(0)
            # Clear the result pane
            self.result_pane.setText("")
        
        SwingUtilities.invokeLater(do_clear)

# --- Main Burp Extender Class ---
class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        """Required by Burp Suite API to register the extension."""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp Thinker")
        
        # Create and register the custom UI tab
        self.tab = BurpThinkerTab(callbacks)
        callbacks.addSuiteTab(self.tab)
        
        callbacks.registerContextMenuFactory(self)
        callbacks.printOutput("[*] Burp Thinker extension loaded successfully")
        callbacks.printOutput("[*] UI Tab 'Burp Thinker' created.")
        callbacks.printOutput("[*] API URL: %s" % API_URL)
        callbacks.printOutput("[*] Token: %s" % ("***" if TOKEN else "NOT SET"))

    def createMenuItems(self, invocation):
        """Create context menu items for Burp Thinker actions."""
        menu = []
        actions = [
            "Analyze Request", "Analyze Response", "Generate XSS Payloads", 
            "Explain CSP", "Explain Stack Trace", "Suggest Fuzzing Strategy", 
            "Summarize Crawl", "Generate Turbo Intruder Script"
        ]
        
        for act in actions:
            menu_item = JMenuItem("Send to AI -> " + act)
            action_id = act.lower().replace(" ", "_")
            menu_item.addActionListener(MenuActionHandler(self, invocation, action_id))
            menu.append(menu_item)
            
        return menu

    def send_action(self, invocation, action):
        """Handle context menu action selection."""
        try:
            self._callbacks.printOutput("[*] Action triggered: %s" % action)
            selected = invocation.getSelectedMessages()
            http_message = selected[0] if selected else None
            
            data_to_send = ""
            target_info = "N/A"

            if not http_message and action not in ["explain_stack_trace", "summarize_crawl"]:
                 self._callbacks.printError("[!] This action requires a selected HTTP message.")
                 return

            if http_message:
                service = http_message.getHttpService()
                target_info = service.getHost() + self._helpers.analyzeRequest(http_message).getUrl().getPath()

            if action in ["explain_stack_trace", "summarize_crawl"]:
                selection_bounds = invocation.getSelectionBounds()
                if not selection_bounds:
                    self._callbacks.printError("[!] Action '%s' requires text selection." % action)
                    return
                
                raw_bytes = http_message.getRequest() if http_message.getRequest() else http_message.getResponse()
                if raw_bytes:
                    data_to_send = self._helpers.bytesToString(raw_bytes[selection_bounds[0]:selection_bounds[1]])
                else:
                    self._callbacks.printError("[!] No HTTP message found for selection.")
                    return
            
            elif action == "explain_csp":
                response_bytes = http_message.getResponse()
                if not response_bytes:
                    self._callbacks.printError("[!] Action 'Explain CSP' requires a response.")
                    return
                
                headers = self._helpers.analyzeResponse(response_bytes).getHeaders()
                csp_header = next((h.split(":", 1)[1].strip() for h in headers if h.lower().startswith("content-security-policy:")), None)
                
                if not csp_header:
                    self._callbacks.printError("[!] No 'Content-Security-Policy' header found in the selected response.")
                    return
                data_to_send = csp_header
            
            else: # For all other actions that operate on a full message
                if action in ["analyze_request", "generate_xss", "suggest_fuzzing_strategy", "generate_turbo_intruder_script"]:
                    msg_bytes = http_message.getRequest()
                else:
                    msg_bytes = http_message.getResponse()

                if not msg_bytes:
                    self._callbacks.printError("[!] Request/Response is None for action: %s" % action)
                    return
                data_to_send = self._helpers.bytesToString(msg_bytes)

            self._callbacks.printOutput("[*] Data length for action '%s': %d bytes" % (action, len(data_to_send)))
            
            start_new_thread(self._do_post, (action, target_info, data_to_send))
            self._callbacks.printOutput("[*] Background task started for action: %s" % action)
            
        except Exception as e:
            self._callbacks.printError("[!] Error in send_action: %s" % str(e))
            import traceback
            self._callbacks.printError(traceback.format_exc())

    def _do_post(self, action, target, data):
        """Send data to the Burp Thinker API and update the UI."""
        try:
            self._callbacks.printOutput("[*] Starting POST request for target: %s" % target)
            
            endpoints = {
                "analyze_request": "/analyze/request", "analyze_response": "/analyze/response",
                "generate_xss": "/payloads/xss", "explain_csp": "/explain/csp",
                "explain_stack_trace": "/explain/stack_trace", "suggest_fuzzing_strategy": "/suggest/fuzzing_strategy",
                "summarize_crawl": "/summarize/crawl", "generate_turbo_intruder_script": "/generate/turbo_intruder_script"
            }
            body_keys = {
                "analyze_request": "request", "analyze_response": "response", "generate_xss": "context",
                "explain_csp": "csp_header", "explain_stack_trace": "stack_trace", "suggest_fuzzing_strategy": "context",
                "summarize_crawl": "crawl_data", "generate_turbo_intruder_script": "base_request"
            }

            url_str = API_URL + endpoints.get(action)
            body = json.dumps({body_keys.get(action): data})

            if not url_str or not body:
                self._callbacks.printError("[!] Unknown action or body key for: %s" % action)
                return

            url = URL(url_str)
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setDoOutput(True)
            conn.setConnectTimeout(10000)
            conn.setReadTimeout(30000)
            conn.setRequestProperty("Authorization", "Bearer " + TOKEN)
            conn.setRequestProperty("Content-Type", "application/json")

            w = OutputStreamWriter(conn.getOutputStream(), "utf-8")
            w.write(body)
            w.flush()
            w.close()

            rcode = conn.getResponseCode()
            self._callbacks.printOutput("[*] Response code: %d" % rcode)
            
            in_stream = BufferedReader(InputStreamReader(conn.getInputStream() if rcode < 400 else conn.getErrorStream(), "utf-8"))
            
            response_text = "".join(iter(in_stream.readLine, None))
            in_stream.close()
            
            self._callbacks.printOutput("[+] Burp Thinker result (HTTP %d):\n%s" % (rcode, response_text))
            
            # If successful, parse the JSON and send it to the UI tab
            if rcode < 400:
                try:
                    result_json = json.loads(response_text)
                    self.tab.add_analysis_result(action, target, result_json)
                except Exception as e:
                    self._callbacks.printError("[!] Failed to parse JSON from response: %s" % str(e))

        except Exception as e:
            self._callbacks.printError("[!] Burp Thinker error in _do_post: %s" % str(e))
            import traceback
            self._callbacks.printError(traceback.format_exc())

# --- Menu Action Handler Class ---
class MenuActionHandler(ActionListener):
    def __init__(self, extender, invocation, action):
        self.extender = extender
        self.invocation = invocation
        self.action = action
    
    def actionPerformed(self, event):
        try:
            self.extender.send_action(self.invocation, self.action)
        except Exception as e:
            self.extender._callbacks.printError("[!] Exception in MenuActionHandler: %s" % str(e))
            import traceback
            self.extender._callbacks.printError(traceback.format_exc())