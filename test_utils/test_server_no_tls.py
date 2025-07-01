import http.server
import ssl
import uuid  # for generating unique session IDs

PORT = 5001

class MyHandler(http.server.BaseHTTPRequestHandler):
    def _send_response(self):
        # Check if client already has a session cookie
        cookie_header = self.headers.get("Cookie", "")
        has_session = "session=" in cookie_header

        self.send_response(200)
        self.send_header("Content-type", "text/html")

        if not has_session:
            session_id = str(uuid.uuid4())
            print(f"🔑 New session created: {session_id}")
            self.send_header("Set-Cookie", f"session={session_id}; HttpOnly; Path=/")

        self.end_headers()

        html = b"<html><body><h1>Hello world</h1></body></html>"
        self.wfile.write(html)

    def do_GET(self):
        self._send_response()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        print(f"📨 Received POST data: {post_data.decode(errors='ignore')}")
        self._send_response()

httpd = http.server.HTTPServer(('0.0.0.0', PORT), MyHandler)

print(f"🚀 Serving HTTP on http://localhost:{PORT}")
httpd.serve_forever()
