# -*- coding: utf-8 -*-
# Jython Burp extension (run under Burp's Jython env).
from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import JMenuItem, JSplitPane, JScrollPane, JTable, JPanel, JButton, JTextPane, JFileChooser
from javax.swing.event import HyperlinkListener, HyperlinkEvent
from java.io import File, FileWriter
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

def safe_unicode(val):
    """Safely converts any value to a unicode string in Jython (Python 2.7)."""
    if val is None:
        return u"N/A"
    if isinstance(val, unicode):
        return val
    if isinstance(val, str):
        try:
            return val.decode('utf-8')
        except Exception:
            try:
                return val.decode('latin-1', 'replace')
            except Exception:
                return unicode(val)
    try:
        return unicode(val)
    except Exception:
        return u"[Unconvertible Value]"

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
        # Add a hyperlink listener to the result pane for interactive links (e.g., download button)
        self.result_pane.addHyperlinkListener(self.on_hyperlink_click)

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
            
            # Extract action and target from the table model
            action = self.history_model.getValueAt(selected_row, 1)
            target = self.history_model.getValueAt(selected_row, 2)
            
            result_data = self.history_data[selected_row]
            self._callbacks.printOutput("[UI DEBUG] Data for row: " + json.dumps(result_data))

            html_content = self._format_json_to_html(result_data, target, action)
            self._callbacks.printOutput("[UI DEBUG] Generated HTML (first 100 chars): " + html_content[:100])
            
            self.result_pane.setText(html_content)
            self.result_pane.setCaretPosition(0)
        except Exception as e:
            self._callbacks.printError("[UI ERROR] Failed in on_history_selection: %s" % str(e))
            import traceback
            self._callbacks.printError(traceback.format_exc())

    def _format_json_to_html(self, data, target=None, action=None):
        """Converts a JSON analysis object into a professional, comprehensive HTML report."""
        try:
            if not isinstance(data, dict):
                return u"<html><pre>" + safe_unicode(data) + u"</pre></html>"

            # Clean, modern CSS tailored for Swing JTextPane and HTML export
            style = u"""
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 10px; color: #24292e; background-color: #ffffff; }
                .header-card { background-color: #f6f8fa; border: 1px solid #e1e4e8; border-left: 6px solid #FF6633; padding: 12px 16px; border-radius: 6px; margin-bottom: 20px; }
                .header-card h1 { margin: 0 0 6px 0; color: #1f2328; font-size: 18px; }
                .header-meta { font-size: 12px; color: #57606a; margin: 2px 0; }
                
                .section-title { color: #1f2328; border-bottom: 2px solid #FF6633; padding-bottom: 4px; margin-top: 24px; margin-bottom: 12px; font-size: 16px; font-weight: bold; }
                
                .summary-box { background-color: #f0f7ff; border: 1px solid #cce5ff; border-left: 4px solid #0969da; padding: 12px 16px; border-radius: 4px; margin-bottom: 16px; line-height: 1.5; font-size: 13px; }
                .conclusion-box { background-color: #f6f8fa; border: 1px solid #d0d7de; border-left: 4px solid #1a7f37; padding: 12px 16px; border-radius: 4px; margin-top: 16px; margin-bottom: 16px; line-height: 1.5; font-size: 13px; }
                
                .metrics-container { margin-bottom: 18px; }
                .badge-metric { display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; margin-right: 6px; }
                
                .badge-critical { background-color: #cf222e; color: #ffffff; }
                .badge-high { background-color: #d1242f; color: #ffffff; }
                .badge-medium { background-color: #bf8700; color: #ffffff; }
                .badge-low { background-color: #1a7f37; color: #ffffff; }
                .badge-info { background-color: #0969da; color: #ffffff; }
                .badge-tag { background-color: #afb8c133; color: #24292f; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-family: monospace; }
                
                table.summary-table { border-collapse: collapse; width: 100%; margin-top: 8px; margin-bottom: 20px; font-size: 12px; }
                table.summary-table th { background-color: #f6f8fa; color: #24292f; border: 1px solid #d0d7de; padding: 8px 10px; text-align: left; font-weight: 600; }
                table.summary-table td { border: 1px solid #d0d7de; padding: 8px 10px; vertical-align: middle; }
                table.summary-table tr:nth-child(even) { background-color: #fcfcfc; }
                
                .finding-card { border: 1px solid #d0d7de; border-radius: 6px; margin-bottom: 20px; background-color: #ffffff; }
                .finding-header { padding: 10px 14px; border-bottom: 1px solid #d0d7de; background-color: #f6f8fa; }
                .finding-header-title { font-size: 14px; font-weight: bold; margin: 0; display: inline-block; }
                .finding-body { padding: 14px; }
                
                .field-row { margin-bottom: 12px; }
                .field-label { font-weight: bold; font-size: 12px; color: #57606a; text-transform: uppercase; margin-bottom: 4px; }
                .field-value { font-size: 13px; line-height: 1.5; color: #24292f; }
                
                code { background-color: #1e1e1e; color: #50fa7b; padding: 2px 5px; border-radius: 3px; font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 12px; }
                pre { background-color: #181818; color: #f8f8f2; border: 1px solid #333333; padding: 10px 12px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 11px; white-space: pre-wrap; word-wrap: break-word; overflow-x: auto; margin: 4px 0 0 0; }
                pre code { background-color: transparent; color: #f8f8f2; padding: 0; }
                
                .btn-download { display: inline-block; padding: 10px 22px; background-color: #1f883d; color: #ffffff; text-decoration: none; font-weight: bold; border-radius: 6px; font-size: 13px; }
            </style>
            """
            
            html = [u"<html><head>", style, u"</head><body>"]
            
            # --- Header Card ---
            html.append(u"<div class='header-card'>")
            html.append(u"<h1>Burp Thinker - Security Assessment Report</h1>")
            if target:
                html.append(u"<div class='header-meta'><strong>Target URL:</strong> <code>" + safe_unicode(target) + u"</code></div>")
            if action:
                html.append(u"<div class='header-meta'><strong>Analysis Action:</strong> " + safe_unicode(action) + u"</div>")
            html.append(u"</div>")
            
            # --- Check if schema is SecurityAssessment (contains 'findings') ---
            if "findings" in data and isinstance(data["findings"], list):
                findings = data["findings"]
                
                # Calculate severity counts
                crit_c = sum(1 for f in findings if safe_unicode(f.get("severity")).lower() == u"critical")
                high_c = sum(1 for f in findings if safe_unicode(f.get("severity")).lower() == u"high")
                med_c  = sum(1 for f in findings if safe_unicode(f.get("severity")).lower() == u"medium")
                low_c  = sum(1 for f in findings if safe_unicode(f.get("severity")).lower() == u"low")
                info_c = sum(1 for f in findings if safe_unicode(f.get("severity")).lower() in [u"informational", u"info"])
                
                # 1. Executive Summary
                exec_sum = data.get("executive_summary")
                if exec_sum:
                    html.append(u"<div class='section-title'>1. Executive Summary</div>")
                    html.append(u"<div class='summary-box'>" + safe_unicode(exec_sum) + u"</div>")
                
                # Severity Metrics Badges
                html.append(u"<div class='metrics-container'>")
                html.append(u"<strong>Severity Overview: </strong> ")
                html.append(u"<span class='badge-metric badge-critical'>Critical: " + safe_unicode(crit_c) + u"</span>")
                html.append(u"<span class='badge-metric badge-high'>High: " + safe_unicode(high_c) + u"</span>")
                html.append(u"<span class='badge-metric badge-medium'>Medium: " + safe_unicode(med_c) + u"</span>")
                html.append(u"<span class='badge-metric badge-low'>Low: " + safe_unicode(low_c) + u"</span>")
                html.append(u"<span class='badge-metric badge-info'>Info: " + safe_unicode(info_c) + u"</span>")
                html.append(u"</div>")
                
                # 2. Vulnerability Summary Table
                html.append(u"<div class='section-title'>2. Vulnerability Summary Table</div>")
                if not findings:
                    html.append(u"<p style='color: #1a7f37;'><strong>✓ No significant security vulnerabilities identified in the evaluated HTTP interaction.</strong></p>")
                else:
                    html.append(u"<table class='summary-table'>")
                    html.append(u"<thead><tr>")
                    html.append(u"<th>#</th>")
                    html.append(u"<th>Stage</th>")
                    html.append(u"<th>Sev</th>")
                    html.append(u"<th>Finding Title</th>")
                    html.append(u"<th>OWASP</th>")
                    html.append(u"<th>MITRE</th>")
                    html.append(u"<th>Confidence</th>")
                    html.append(u"<th>Exploitability</th>")
                    html.append(u"</tr></thead><tbody>")
                    
                    for idx, finding in enumerate(findings, start=1):
                        sev = safe_unicode(finding.get("severity", "Informational"))
                        sev_lower = sev.lower()
                        badge_cls = "badge-info"
                        if "crit" in sev_lower: badge_cls = "badge-critical"
                        elif "high" in sev_lower: badge_cls = "badge-high"
                        elif "med" in sev_lower: badge_cls = "badge-medium"
                        elif "low" in sev_lower: badge_cls = "badge-low"
                        
                        html.append(u"<tr>")
                        html.append(u"<td>" + safe_unicode(idx) + u"</td>")
                        html.append(u"<td><span class='badge-tag'>" + safe_unicode(finding.get("stage", "Analysis")) + u"</span></td>")
                        html.append(u"<td><span class='badge-metric " + badge_cls + u"'>" + sev + u"</span></td>")
                        html.append(u"<td><strong>" + safe_unicode(finding.get("title", "Untitled")) + u"</strong></td>")
                        html.append(u"<td><span class='badge-tag'>" + safe_unicode(finding.get("owasp", "N/A")) + u"</span></td>")
                        html.append(u"<td><span class='badge-tag'>" + safe_unicode(finding.get("mitre", "N/A")) + u"</span></td>")
                        html.append(u"<td>" + safe_unicode(finding.get("confidence", "Potential")) + u"</td>")
                        html.append(u"<td>" + safe_unicode(finding.get("exploitability", "Medium")) + u"</td>")
                        html.append(u"</tr>")
                    
                    html.append(u"</tbody></table>")
                    
                    # 3. Detailed Findings Section
                    html.append(u"<div class='section-title'>3. Detailed Findings Breakdown</div>")
                    for idx, finding in enumerate(findings, start=1):
                        sev = safe_unicode(finding.get("severity", "Informational"))
                        sev_lower = sev.lower()
                        badge_cls = "badge-info"
                        if "crit" in sev_lower: badge_cls = "badge-critical"
                        elif "high" in sev_lower: badge_cls = "badge-high"
                        elif "med" in sev_lower: badge_cls = "badge-medium"
                        elif "low" in sev_lower: badge_cls = "badge-low"
                        
                        html.append(u"<div class='finding-card'>")
                        html.append(u"<div class='finding-header'>")
                        html.append(u"<span class='badge-metric " + badge_cls + u"'>" + sev + u"</span> ")
                        html.append(u"<span class='finding-header-title'>#" + safe_unicode(idx) + u" - " + safe_unicode(finding.get("title")) + u"</span>")
                        html.append(u"</div>")
                        
                        html.append(u"<div class='finding-body'>")
                        
                        # Description
                        html.append(u"<div class='field-row'><div class='field-label'>Description</div>")
                        html.append(u"<div class='field-value'>" + safe_unicode(finding.get("description")) + u"</div></div>")
                        
                        # Payload / Evidence
                        evidence = finding.get("evidence") or finding.get("payload")
                        if evidence:
                            html.append(u"<div class='field-row'><div class='field-label'>Payload / Observed Evidence</div>")
                            html.append(u"<pre><code>" + safe_unicode(evidence).replace(u"<", u"&lt;").replace(u">", u"&gt;") + u"</code></pre></div>")
                        
                        # POC (Proof of Concept)
                        poc = finding.get("poc")
                        if poc:
                            html.append(u"<div class='field-row'><div class='field-label'>Proof of Concept (PoC)</div>")
                            html.append(u"<pre><code>" + safe_unicode(poc).replace(u"<", u"&lt;").replace(u">", u"&gt;") + u"</code></pre></div>")
                        
                        # Impact
                        impact = finding.get("impact")
                        if impact:
                            html.append(u"<div class='field-row'><div class='field-label'>Impact</div>")
                            html.append(u"<div class='field-value'>" + safe_unicode(impact) + u"</div></div>")
                        
                        # Next Steps
                        next_steps = finding.get("next_steps")
                        if next_steps:
                            html.append(u"<div class='field-row'><div class='field-label'>Next Steps (Verification)</div>")
                            html.append(u"<div class='field-value'>" + safe_unicode(next_steps) + u"</div></div>")
                        
                        # Remediation
                        remediation = finding.get("remediation")
                        if remediation:
                            html.append(u"<div class='field-row'><div class='field-label'>Remediation</div>")
                            html.append(u"<div class='field-value'>" + safe_unicode(remediation) + u"</div></div>")
                        
                        html.append(u"</div></div>") # end finding-body & finding-card
                
                # 4. Conclusion
                conclusion = data.get("conclusion")
                if conclusion:
                    html.append(u"<div class='section-title'>4. Conclusion</div>")
                    html.append(u"<div class='conclusion-box'>" + safe_unicode(conclusion) + u"</div>")
            
            # --- Turbo Intruder Script schema ---
            elif "script_code" in data:
                html.append(u"<div class='section-title'>Turbo Intruder Script</div>")
                html.append(u"<pre><code>" + safe_unicode(data.get("script_code", "")).replace(u"<", u"&lt;").replace(u">", u"&gt;") + u"</code></pre>")
                html.append(u"<div class='section-title'>Explanation</div><p>" + safe_unicode(data.get("explanation", "")) + u"</p>")
                if data.get("suggested_payloads"):
                    html.append(u"<div class='section-title'>Suggested Payloads</div><ul>")
                    for item in data["suggested_payloads"]:
                        html.append(u"<li><code>" + safe_unicode(item).replace(u"<", u"&lt;").replace(u">", u"&gt;") + u"</code></li>")
                    html.append(u"</ul>")
            
            # --- Generic Payload List schema ---
            elif "payloads" in data:
                html.append(u"<div class='section-title'>Generated Payloads</div><ul>")
                for item in data["payloads"]:
                    html.append(u"<li><code>" + safe_unicode(item).replace(u"<", u"&lt;").replace(u">", u"&gt;") + u"</code></li>")
                html.append(u"</ul>")

            # --- Generic Analysis Fallback schema ---
            else:
                for key, value in data.items():
                    title = safe_unicode(key).replace(u"_", u" ").title()
                    html.append(u"<div class='section-title'>" + title + u"</div>")
                    
                    if isinstance(value, list) and value:
                        html.append(u"<ul>")
                        for item in value:
                            html.append(u"<li>" + safe_unicode(item).replace(u"<", u"&lt;").replace(u">", u"&gt;") + u"</li>")
                        html.append(u"</ul>")
                    elif isinstance(value, dict) and value:
                        html.append(u"<ul>")
                        for k, v in value.items():
                            html.append(u"<li><strong>" + safe_unicode(k) + u":</strong> " + safe_unicode(v).replace(u"<", u"&lt;").replace(u">", u"&gt;") + u"</li>")
                        html.append(u"</ul>")
                    elif isinstance(value, (str, unicode)) and value:
                        val_unicode = safe_unicode(value)
                        if u"def " in val_unicode or u"import " in val_unicode or u"{" in val_unicode:
                            html.append(u"<pre><code>" + val_unicode.replace(u"<", u"&lt;").replace(u">", u"&gt;") + u"</code></pre>")
                        else:
                            html.append(u"<p>" + val_unicode + u"</p>")
                    elif value is not None:
                        html.append(u"<p>" + safe_unicode(value) + u"</p>")
                    else:
                        html.append(u"<p>N/A</p>")

            # Download Report Button
            html.append(u"<div style=\"text-align: center; margin: 30px 0 10px 0;\"><a href=\"download_html_report\" class=\"btn-download\">Download HTML Report</a></div>")
            html.append(u"</body></html>")
            return u"".join(html)
        except Exception as e:
            self._callbacks.printError("[UI ERROR] Failed in _format_json_to_html: %s" % str(e))
            import traceback
            self._callbacks.printError(traceback.format_exc())
            return u"<html><body><h2>Error rendering HTML</h2><p>Check the Burp Extender error console for details.</p></body></html>"
            return u"".join(html)
        except Exception as e:
            self._callbacks.printError("[UI ERROR] Failed in _format_json_to_html: %s" % str(e))
            import traceback
            self._callbacks.printError(traceback.format_exc())
            return u"<html><body><h2>Error rendering HTML</h2><p>Check the Burp Extender error console for details.</p></body></html>"

    def clear_history(self, event):
        def do_clear():
            self.history_data = []
            # Clear the table model
            while self.history_model.getRowCount() > 0:
                self.history_model.removeRow(0)
            # Clear the result pane
            self.result_pane.setText("")
        
        SwingUtilities.invokeLater(do_clear)

    def on_hyperlink_click(self, event):
        if event.getEventType() == HyperlinkEvent.EventType.ACTIVATED:
            if event.getDescription() == "download_html_report":
                self.download_html_report()

    def download_html_report(self):
        file_chooser = JFileChooser()
        file_chooser.setSelectedFile(File("burp_thinker_report.html"))
        
        ret = file_chooser.showSaveDialog(self._main_panel)
        
        if ret == JFileChooser.APPROVE_OPTION:
            file = file_chooser.getSelectedFile()
            try:
                writer = FileWriter(file)
                writer.write(self.result_pane.getText())
                writer.close()
                self._callbacks.printOutput("[UI INFO] HTML report saved to: %s" % file.getAbsolutePath())
            except Exception as e:
                self._callbacks.printError("[UI ERROR] Failed to save HTML report: %s" % str(e))
                import traceback
                self._callbacks.printError(traceback.format_exc())

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
            
        # Add a separator for the new, more powerful action
        menu.append(JMenuItem("---"))

        # Analyze Request/Response Pair
        m9 = JMenuItem("Send to AI -> Analyze Request/Response Pair")
        m9.addActionListener(MenuActionHandler(self, invocation, "analyze_http_pair"))
        menu.append(m9)
        
        return menu

    def send_action(self, invocation, action):
        """Handle context menu action selection."""
        try:
            self._callbacks.printOutput("[*] Action triggered: %s" % action)
            selected = invocation.getSelectedMessages()
            http_message = selected[0] if selected else None
            
            data_to_send = {} # Use a dict for actions that need multiple parts
            target_info = "N/A"

            if not http_message:
                 self._callbacks.printError("[!] This action requires a selected HTTP message.")
                 return

            if http_message:
                service = http_message.getHttpService()
                target_info = service.getHost() + self._helpers.analyzeRequest(http_message).getUrl().getPath()

            if action == "analyze_http_pair":
                request_bytes = http_message.getRequest()
                response_bytes = http_message.getResponse()
                if not request_bytes or not response_bytes:
                    self._callbacks.printError("[!] Action 'Analyze Request/Response Pair' requires a message with both a request and a response.")
                    return
                data_to_send = {
                    "request": self._helpers.bytesToString(request_bytes),
                    "response": self._helpers.bytesToString(response_bytes)
                }

            elif action in ["explain_stack_trace", "summarize_crawl"]:
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
            
            else: # For all other actions that operate on a single full message
                if action in ["analyze_request", "generate_xss", "suggest_fuzzing_strategy", "generate_turbo_intruder_script"]:
                    msg_bytes = http_message.getRequest()
                else:
                    msg_bytes = http_message.getResponse()

                if not msg_bytes:
                    self._callbacks.printError("[!] Request/Response is None for action: %s" % action)
                    return
                data_to_send = self._helpers.bytesToString(msg_bytes)

            self._callbacks.printOutput("[*] Preparing data for action '%s'" % action)
            
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
                "summarize_crawl": "/summarize/crawl", "generate_turbo_intruder_script": "/generate/turbo_intruder_script",
                "analyze_http_pair": "/analyze/http_pair"
            }
            
            # For the new http_pair action, the data is already a dict.
            # For others, we build the dict.
            if action == "analyze_http_pair":
                body = json.dumps(data)
            else:
                body_keys = {
                    "analyze_request": "request", "analyze_response": "response", "generate_xss": "context",
                    "explain_csp": "csp_header", "explain_stack_trace": "stack_trace", "suggest_fuzzing_strategy": "context",
                    "summarize_crawl": "crawl_data", "generate_turbo_intruder_script": "base_request"
                }
                body = json.dumps({body_keys.get(action): data})

            url_str = API_URL + endpoints.get(action)

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