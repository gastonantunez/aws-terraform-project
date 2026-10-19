from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        mensaje = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Proyecto AWS</title>
</head>
<body>
    <h1>Despliegue automatico funcionando</h1>
    <p>Esta respuesta viene de Python.</p>
    <p>Nginx esta funcionando como reverse proxy.</p>
</body>
</html>
"""

        contenido = mensaje.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(contenido)))
        self.end_headers()
        self.wfile.write(contenido)


server = HTTPServer(("0.0.0.0", 3000), Handler)

print("Aplicacion escuchando en el puerto 3000")

server.serve_forever()
