import socket, threading
def serve(port, banner, linger=True):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(64)
    def loop():
        while True:
            try:
                c, _ = s.accept()
                if banner: c.sendall(banner)
                if not linger: c.close()
                else: threading.Timer(2.0, c.close).start()
            except Exception: pass
    threading.Thread(target=loop, daemon=True).start()
serve(2222, b"SSH-2.0-OpenSSH_7.4\r\n")
serve(2525, b"220 mail.lab.test ESMTP Postfix (Ubuntu)\r\n")
serve(6379, b"")            # silent: nmap must fall back / stay unsure
import http.server, socketserver, threading as th
class H(http.server.SimpleHTTPRequestHandler):
    server_version = "Apache/2.4.49"; sys_version = "(Unix)"
    def log_message(self, *a): pass
httpd = socketserver.TCPServer(("127.0.0.1", 8080), H)
th.Thread(target=httpd.serve_forever, daemon=True).start()
print("listeners up", flush=True)
import time
while True: time.sleep(3600)
