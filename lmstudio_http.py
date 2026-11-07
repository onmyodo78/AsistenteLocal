"""Transporte privado para el único endpoint autorizado, sin reintentos."""
import http.client
import socket
import time
import urllib.error
import urllib.request

ENDPOINT = 'http://127.0.0.1:1234/v1/chat/completions'


def restante(deadline):
    segundos = deadline - time.monotonic()
    if segundos <= 0:
        raise TimeoutError('Plazo HTTP agotado.')
    return segundos


class SocketConPlazo(socket.socket):
    """SocketIO usa recv_into: cada recepción descuenta el mismo reloj."""
    def __init__(self, deadline):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.deadline = deadline

    def connect(self, address):
        self.settimeout(restante(self.deadline))
        return super().connect(address)

    def sendall(self, data, flags=0):
        self.settimeout(restante(self.deadline))
        return super().sendall(data, flags)

    def recv_into(self, buffer, nbytes=0, flags=0):
        self.settimeout(restante(self.deadline))
        return super().recv_into(buffer, nbytes, flags)


class SinRedireccion(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def abrir_http_local(request, timeout, medicion, deadline):
    # Validación previa a construir el transporte; sin DNS, proxies ni túneles.
    if request.full_url != ENDPOINT or request.get_method() != 'POST':
        raise ValueError('Endpoint HTTP no autorizado.')
    limite = min(deadline, time.monotonic() + timeout)

    class Conexion(http.client.HTTPConnection):
        def connect(self):
            if self.host != '127.0.0.1' or self.port != 1234 or self._tunnel_host:
                raise ValueError('Destino HTTP no autorizado.')
            medicion.fase('conexion_tcp')
            self.sock = SocketConPlazo(limite)
            try:
                self.sock.connect(('127.0.0.1', 1234))
                restante(limite)
            except BaseException:
                self.close()
                raise

        def request(self, *args, **kwargs):
            self.connect()
            medicion.fase('envio_peticion')
            restante(limite)
            super().request(*args, **kwargs)
            restante(limite)

        def getresponse(self):
            medicion.fase('espera_cabeceras')
            restante(limite)
            respuesta = super().getresponse()
            try:
                restante(limite)
            except BaseException:
                respuesta.close()
                raise
            return respuesta

    class Manejador(urllib.request.HTTPHandler):
        def http_open(self, req):
            if req.full_url != ENDPOINT or req.host != '127.0.0.1:1234':
                raise ValueError('Destino HTTP no autorizado.')
            return self.do_open(Conexion, req)

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), SinRedireccion(), Manejador())
    return opener.open(request, timeout=restante(limite))
