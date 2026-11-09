#!/usr/bin/env python3
"""Entrada independiente al circuito APT existente, sin LM Studio ni contraseñas."""
import argparse
import os
import sys

OPERACIONES = ('diagnostico-mantenimiento', 'plan', 'plan-descarga-apt',
               'comprobar-ejecucion-apt', 'descargar-apt', 'actualizar-apt', 'historial-apt')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Mantenimiento APT independiente; helper protegido existente')
    parser.add_argument('--formato', choices=('texto', 'json'), default='texto')
    parser.add_argument('operacion', choices=OPERACIONES)
    args = parser.parse_args(argv)
    if args.operacion in ('descargar-apt', 'actualizar-apt', 'historial-apt'):
        # No utilizar stdin para contraseñas ni ofrecer ejecución programada privilegiada.
        try:
            fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY)
            try:
                if not os.isatty(fd):
                    raise OSError('terminal_requerido')
            finally:
                os.close(fd)
        except OSError:
            print('Se requiere un terminal interactivo. No se inició la operación.', file=sys.stderr)
            return 1
    from cli import main as cli_main
    return cli_main(['--formato', args.formato, args.operacion])


if __name__ == '__main__':
    sys.exit(main())
