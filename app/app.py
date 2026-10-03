from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()

        mensaje = """
        <html>
        <body>
            <h1>Mi aplicación está funcionando</h1>
            <p>Esta respuesta viene de Python.</p>
            <p>Nginx está funcionando como reverse proxy.</p>
        </body>
        </html>
        """

        self.wfile.write(mensaje.encode())

server = HTTPServer(("0.0.0.0", 3000), Handler)

print("Aplicación escuchando en el puerto 3000")

server.serve_forever()
