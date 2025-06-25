import http.server
import ssl
import uuid
from socketserver import ThreadingMixIn

PORT = 5001
CERT_FILE = "../server-cert.pem"
KEY_FILE = "../server-key.pem"

class MyHandler(http.server.BaseHTTPRequestHandler):
    def _send_response(self):
        cookie_header = self.headers.get("Cookie", "")
        has_session = "session=" in cookie_header

        self.send_response(200)
        self.send_header("Content-type", "text/html")

        if not has_session:
            session_id = str(uuid.uuid4())
            print(f"🔑 New session created: {session_id}")
            self.send_header("Set-Cookie", f"session={session_id}; HttpOnly; Path=/")

        self.end_headers()
        html = b"<html><body><h1>GRAZIEDARIOGRAZIEDARIOGRAZIEDP1=</h1></body></html>"
        self.wfile.write(html)

    def do_GET(self):
        self._send_response()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        print(f"📨 Received POST data: {post_data.decode(errors='ignore')}")
        self._send_response()

class ThreadedHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True  # allows clean exit on Ctrl+C

httpd = ThreadedHTTPServer(('0.0.0.0', PORT), MyHandler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print(f"🚀 Serving threaded HTTPS on https://localhost:{PORT}")
httpd.serve_forever()
