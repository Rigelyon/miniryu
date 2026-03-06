import re
import json

with open('main.py', 'r') as f:
    text = f.read()

# Remove the SDNControllerRestAPI class
text = re.sub(r'class SDNControllerRestAPI\(ControllerBase\):.*', '', text, flags=re.DOTALL)

# Remove old unused imports
text = text.replace('from webob import Response\n', '')
text = text.replace('from ryu.app.wsgi import ControllerBase, WSGIApplication, route\n', '')
text = text.replace('REST_INSTANCE_NAME = "sdn_rest_api"\n', '')
text = text.replace('REST_BASE_PATH = "/api"\n', '')
text = text.replace('    _CONTEXTS = {"wsgi": WSGIApplication}\n', '')
text = text.replace('    # _CONTEXTS = {"wsgi": WSGIApplication}\n', '')

# add custom server logic directly inside the main app class
new_methods = """
    def _start_custom_rest_server(self, port=8080):
        try:
            server = eventlet.listen(('0.0.0.0', port))
            self.sec_logger.log_event("api", "Starting eventlet raw API server on port "+str(port))
            while True:
                client, addr = server.accept()
                eventlet.spawn(self._handle_api_request, client)
        except Exception as e:
            self.sec_logger.log_event("api_error", str(e), severity="error")

    def _handle_api_request(self, client):
        try:
            data = client.recv(4096).decode('utf-8', errors='ignore')
            if not data:
                return
            lines = data.split('\\r\\n')
            if not lines:
                return
            req_line = lines[0].split(' ')
            if len(req_line) < 2:
                return
            method, path = req_line[0], req_line[1]

            response = {}
            status = "200 OK"

            if path == '/api/status' and method == 'GET':
                response = self.get_status()
            elif path == '/api/attacks' and method == 'GET':
                response = [self._format_event(e) for e in self.sec_logger.get_recent_attacks(limit=100)]
            elif path == '/api/block_ip' and method == 'POST':
                try:
                    body_start = data.find('\\r\\n\\r\\n') + 4
                    if body_start >= 4:
                        body_text = data[body_start:]
                        import json
                        body = json.loads(body_text) if body_text.strip() else {}
                        ip = body.get('ip')
                        duration = int(body.get('duration', 120))
                        if ip:
                            self.block_ip(ip, duration=duration, reason="api")
                            response = {"status": "ok", "blocked_ip": ip}
                        else:
                            status = "400 Bad Request"
                            response = {"error": "missing ip field"}
                    else:
                        status = "400 Bad Request"
                        response = {"error": "missing body"}
                except Exception as e:
                    status = "400 Bad Request"
                    response = {"error": str(e)}
            elif path == '/api/load_balancer/enable' and method == 'POST':
                self.enable_load_balancer()
                response = {"status": "enabled"}
            elif path == '/api/load_balancer/disable' and method == 'POST':
                self.disable_load_balancer()
                response = {"status": "disabled"}
            elif path == '/health' and method == 'GET':
                response = {"status": "ok"}
            else:
                status = "404 Not Found"
                response = {"error": "not found"}

            import json
            res_body = json.dumps(response)
            res_headers = (
                "HTTP/1.1 " + status + "\\r\\n"
                "Content-Type: application/json\\r\\n"
                "Access-Control-Allow-Origin: *\\r\\n"
                "Content-Length: " + str(len(res_body)) + "\\r\\n"
                "Connection: close\\r\\n\\r\\n"
            )
            client.sendall((res_headers + res_body).encode('utf-8'))
        except Exception as e:
            pass
        finally:
            client.close()
"""

with open('main.py', 'w') as f:
    f.write(text.rstrip() + "\n" + new_methods)

print("Patch applied.")
