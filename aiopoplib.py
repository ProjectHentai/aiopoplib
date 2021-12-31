"""An Asyncio POP3 client class.

Based on the J. Myers POP3 draft, Jan. 96
"""

# Author: Synodriver <diguohuangjiajinweijun@gmail.com>
#         [heavily stealing from stdlib]

# Example (see the test function at the end of this file)

# Imports
import sys
import asyncio
import re
from typing import Tuple

try:
    import ssl

    HAVE_SSL = True
except ImportError:
    HAVE_SSL = False

__all__ = ["POP3", "error_proto"]


# Exception raised when an error or invalid response is received:

class error_proto(Exception):
    pass


# Standard Port
POP3_PORT = 110

# POP SSL PORT
POP3_SSL_PORT = 995

# Line terminators (we always output CRLF, but accept any of CRLF, LFCR, LF)
CR = b'\r'
LF = b'\n'
CRLF = CR + LF

# maximal line length when calling readline(). This is to prevent
# reading arbitrary length lines. RFC 1939 limits POP3 line length to
# 512 characters, including CRLF. We have selected 2048 just to be on
# the safe side.
_MAXLINE = 2048


class TCPSocket:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer

    @classmethod
    async def create_connection(cls, host: str, port: int, timeout: float, ssl: ssl.SSLContext = None) -> "TCPSocket":
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ssl), timeout)
        return cls(reader, writer)

    async def sendall(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def read(self, n: int = -1) -> bytes:
        return await self._reader.read(n)

    async def readexactly(self, n: int) -> bytes:
        return await self._reader.readexactly(n)

    async def readline(self, size: int = -1) -> bytes:
        if size == -1:
            return await self._reader.readline()
        else:
            buffer = bytearray()
            for _ in range(size):
                data = await self.readexactly(1)
                if data != b"\n":
                    buffer.extend(data)
                else:
                    break
            return bytes(buffer)

    async def close(self) -> None:
        self._writer.close()
        await self._writer.wait_closed()


class POP3:
    """This class supports both the minimal and optional command sets.
    Arguments can be strings or integers (where appropriate)
    (e.g.: retr(1) and retr('1') both work equally well.

    Minimal Command Set:
            USER name               user(name)
            PASS string             pass_(string)
            STAT                    stat()
            LIST [msg]              list(msg = None)
            RETR msg                retr(msg)
            DELE msg                dele(msg)
            NOOP                    noop()
            RSET                    rset()
            QUIT                    quit()

    Optional Commands (some servers support these):
            RPOP name               rpop(name)
            APOP name digest        apop(name, digest)
            TOP msg n               top(msg, n)
            UIDL [msg]              uidl(msg = None)
            CAPA                    capa()
            STLS                    stls()
            UTF8                    utf8()

    Raises one exception: 'error_proto'.

    Instantiate with:
            POP3(hostname, port=110)

    NB:     the POP protocol locks the mailbox from user
            authorization until QUIT, so be sure to get in, suck
            the messages, and quit, each time you access the
            mailbox.

            POP is a line-based protocol, which means large mail
            messages consume lots of python cycles reading them
            line-by-line.

            If it's available on your mail server, use IMAP4
            instead, it doesn't suffer from the two problems
            above.
    """

    encoding = 'UTF-8'

    def __init__(self, host, port=POP3_PORT,
                 timeout=1):
        self.host = host
        self.port = port
        self._tls_established = False
        sys.audit("poplib.connect", self, host, port)
        self.sock = None  # type: TCPSocket
        self.timeout = timeout
        # self.file = self.sock.makefile('rb')
        self._debugging = 0
        self.welcome = None  # type: bytes

    async def connect(self):
        """
        need coonnect first
        :return:
        """
        assert self.sock is None
        self.sock = await self._create_socket(self.timeout)
        self.welcome = await self._getresp()

    async def _create_socket(self, timeout, ssl: ssl.SSLContext = None) -> TCPSocket:
        return await TCPSocket.create_connection(self.host, self.port, timeout, ssl)

    async def _putline(self, line):
        if self._debugging > 1:
            print('*put*', repr(line))
        sys.audit("poplib.putline", self, line)
        await self.sock.sendall(line + CRLF)

    # Internal: send one command to the server (through _putline())

    async def _putcmd(self, line):
        if self._debugging:
            print('*cmd*', repr(line))
        line = bytes(line, self.encoding)
        await self._putline(line)

    # Internal: return one line from the server, stripping CRLF.
    # This is where all the CPU time of this module is consumed.
    # Raise error_proto('-ERR EOF') if the connection is closed.

    async def _getline(self) -> Tuple[bytes, int]:
        line = await self.sock.readline(_MAXLINE + 1)
        if len(line) > _MAXLINE:
            raise error_proto('line too long')

        if self._debugging > 1:
            print('*get*', repr(line))
        if not line:
            raise error_proto('-ERR EOF')
        octets = len(line)
        # server can send any combination of CR & LF
        # however, 'readline()' returns lines ending in LF
        # so only possibilities are ...LF, ...CRLF, CR...LF
        if line[-2:] == CRLF:
            return line[:-2], octets
        if line[:1] == CR:
            return line[1:-1], octets
        return line[:-1], octets

    # Internal: get a response from the server.
    # Raise 'error_proto' if the response doesn't start with '+'.

    async def _getresp(self) -> bytes:
        resp, o = await self._getline()
        if self._debugging > 1:
            print('*resp*', repr(resp))
        if not resp.startswith(b'+'):
            raise error_proto(resp)
        return resp

    # Internal: get a response plus following text from the server.

    async def _getlongresp(self):
        resp = await self._getresp()
        list = [];
        octets = 0
        line, o = await self._getline()
        while line != b'.':
            if line.startswith(b'..'):
                o = o - 1
                line = line[1:]
            octets = octets + o
            list.append(line)
            line, o = await self._getline()
        return resp, list, octets

    # Internal: send a command and get the response

    async def _shortcmd(self, line):
        await self._putcmd(line)
        return await self._getresp()

    # Internal: send a command and get the response plus following text

    async def _longcmd(self, line):
        await self._putcmd(line)
        return await self._getlongresp()

    # These can be useful:

    def getwelcome(self):
        return self.welcome

    def set_debuglevel(self, level):
        self._debugging = level

    # Here are all the POP commands:

    async def user(self, user):
        """Send user name, return response

        (should indicate password required).
        """
        return await self._shortcmd('USER %s' % user)

    async def pass_(self, pswd):
        """Send password, return response

        (response includes message count, mailbox size).

        NB: mailbox is locked by server from here to 'quit()'
        """
        return await self._shortcmd('PASS %s' % pswd)

    async def stat(self):
        """Get mailbox status.

        Result is tuple of 2 ints (message count, mailbox size)
        """
        retval = await self._shortcmd('STAT')
        rets = retval.split()
        if self._debugging:
            print('*stat*', repr(rets))
        numMessages = int(rets[1])
        sizeMessages = int(rets[2])
        return (numMessages, sizeMessages)

    async def list(self, which=None):
        """Request listing, return result.

        Result without a message number argument is in form
        ['response', ['mesg_num octets', ...], octets].

        Result when a message number argument is given is a
        single response: the "scan listing" for that message.
        """
        if which is not None:
            return await self._shortcmd('LIST %s' % which)
        return await self._longcmd('LIST')

    async def retr(self, which):
        """Retrieve whole message number 'which'.

        Result is in form ['response', ['line', ...], octets].
        """
        return await self._longcmd('RETR %s' % which)

    async def dele(self, which):
        """Delete message number 'which'.

        Result is 'response'.
        """
        return await self._shortcmd('DELE %s' % which)

    async def noop(self):
        """Does nothing.

        One supposes the response indicates the server is alive.
        """
        return await self._shortcmd('NOOP')

    async def rset(self):
        """Unmark all messages marked for deletion."""
        return await self._shortcmd('RSET')

    async def quit(self):
        """Signoff: commit changes on server, unlock mailbox, close connection."""
        resp = await self._shortcmd('QUIT')
        await self.close()
        return resp

    async def close(self):
        """Close the connection without assuming anything about it."""
        await self.sock.close()

    # __del__ = quit

    # optional commands:

    async def rpop(self, user):
        """Not sure what this does."""
        return await self._shortcmd('RPOP %s' % user)

    timestamp = re.compile(br'\+OK.[^<]*(<.*>)')

    async def apop(self, user, password):
        """Authorisation

        - only possible if server has supplied a timestamp in initial greeting.

        Args:
                user     - mailbox user;
                password - mailbox password.

        NB: mailbox is locked by server from here to 'quit()'
        """
        secret = bytes(password, self.encoding)
        m = self.timestamp.match(self.welcome)
        if not m:
            raise error_proto('-ERR APOP not supported by server')
        import hashlib
        digest = m.group(1) + secret
        digest = hashlib.md5(digest).hexdigest()
        return await self._shortcmd('APOP %s %s' % (user, digest))

    async def top(self, which, howmuch):
        """Retrieve message header of message number 'which'
        and first 'howmuch' lines of message body.

        Result is in form ['response', ['line', ...], octets].
        """
        return await self._longcmd('TOP %s %s' % (which, howmuch))

    async def uidl(self, which=None):
        """Return message digest (unique id) list.

        If 'which', result contains unique id for that message
        in the form 'response mesgnum uid', otherwise result is
        the list ['response', ['mesgnum uid', ...], octets]
        """
        if which is not None:
            return await self._shortcmd('UIDL %s' % which)
        return await self._longcmd('UIDL')

    async def utf8(self):
        """Try to enter UTF-8 mode (see RFC 6856). Returns server response.
        """
        return await self._shortcmd('UTF8')

    async def capa(self):
        """Return server capabilities (RFC 2449) as a dictionary
        >>> c=aiopoplib.POP3('localhost')
        >>> await c.capa()
        {'IMPLEMENTATION': ['Cyrus', 'POP3', 'server', 'v2.2.12'],
         'TOP': [], 'LOGIN-DELAY': ['0'], 'AUTH-RESP-CODE': [],
         'EXPIRE': ['NEVER'], 'USER': [], 'STLS': [], 'PIPELINING': [],
         'UIDL': [], 'RESP-CODES': []}
        >>>

        Really, according to RFC 2449, the cyrus folks should avoid
        having the implementation split into multiple arguments...
        """

        def _parsecap(line):
            lst = line.decode('ascii').split()
            return lst[0], lst[1:]

        caps = {}
        try:
            resp = await self._longcmd('CAPA')
            rawcaps = resp[1]
            for capline in rawcaps:
                capnm, capargs = _parsecap(capline)
                caps[capnm] = capargs
        except error_proto as _err:
            raise error_proto('-ERR CAPA not supported by server')
        return caps

    async def stls(self, context: ssl.SSLContext = None):
        """Start a TLS session on the active connection as specified in RFC 2595.

                context - a ssl.SSLContext
        """
        raise NotImplementedError
        # if not HAVE_SSL:
        #     raise error_proto('-ERR TLS support missing')
        # if self._tls_established:
        #     raise error_proto('-ERR TLS session already established')
        # caps = self.capa()
        # if not 'STLS' in caps:
        #     raise error_proto('-ERR STLS not supported by server')
        # if context is None:
        #     context = ssl._create_stdlib_context()
        # resp = await self._shortcmd('STLS')
        # self.sock = context.wrap_socket(self.sock,
        #                                 server_hostname=self.host)
        # self.file = self.sock.makefile('rb')
        # self._tls_established = True
        # return resp


if HAVE_SSL:

    class POP3_SSL(POP3):
        """POP3 client class over SSL connection

        Instantiate with: POP3_SSL(hostname, port=995, keyfile=None, certfile=None,
                                   context=None)

               hostname - the hostname of the pop3 over ssl server
               port - port number
               keyfile - PEM formatted file that contains your private key
               certfile - PEM formatted certificate chain file
               context - a ssl.SSLContext

        See the methods of the parent class POP3 for more documentation.
        """

        def __init__(self, host, port=POP3_SSL_PORT, keyfile=None, certfile=None,
                     timeout=1, context=None):
            if context is not None and keyfile is not None:
                raise ValueError("context and keyfile arguments are mutually "
                                 "exclusive")
            if context is not None and certfile is not None:
                raise ValueError("context and certfile arguments are mutually "
                                 "exclusive")
            if keyfile is not None or certfile is not None:
                import warnings
                warnings.warn("keyfile and certfile are deprecated, use a "
                              "custom context instead", DeprecationWarning, 2)
            self.keyfile = keyfile
            self.certfile = certfile
            if context is None:
                context = ssl._create_stdlib_context(certfile=certfile,
                                                     keyfile=keyfile)
            self.context = context  # type: ssl.SSLContext
            super().__init__(host, port, timeout)

        async def _create_socket(self, timeout, ssl: ssl.SSLContext = None):
            sock = await super()._create_socket(timeout, ssl=self.context)
            return sock

        def stls(self, keyfile=None, certfile=None, context=None):
            """The method unconditionally raises an exception since the
            STLS command doesn't make any sense on an already established
            SSL/TLS session.
            """
            raise error_proto('-ERR TLS session already established')


    __all__.append("POP3_SSL")


async def main(argv):
    a = POP3(argv[1])
    await a.connect()
    print(a.getwelcome())
    await a.user(argv[2])
    await a.pass_(argv[3])
    await a.list()
    (numMsgs, totalSize) = await a.stat()
    for i in range(1, numMsgs + 1):
        (header, msg, octets) = await a.retr(i)
        print("Message %d:" % i)
        for line in msg:
            print('   ' + line)
        print('-----------------------')
    await a.quit()


if __name__ == "__main__":
    import sys

    asyncio.run(main(sys.argv))
