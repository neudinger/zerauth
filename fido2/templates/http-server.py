import http.server
import ssl
import socketserver

# Set the port you want to use (e.g., 4443 is often used for local HTTPS)
PORT = 443

# The request handler is the same as the simple HTTP server
HANDLER = http.server.SimpleHTTPRequestHandler

# Set up the SSL/TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

# openssl req -new -x509 -keyout key.pem -out cert.pem -days 365 -nodes
# cp cert.pem /usr/local/share/ca-certificates/localhost.crt 
#  update-ca-certificates --fresh
# Create the server
with socketserver.TCPServer(("0.0.0.0", PORT), HANDLER) as httpd:
    # Wrap the server's socket with the SSL context
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"Serving securely at https://localhost:{PORT}")
    httpd.serve_forever()
