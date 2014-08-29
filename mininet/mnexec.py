"""
This is an attempt to modularize the required mechanism to startup a
container-based experiment.
"""
from subprocess import Popen, PIPE, check_output as co
import time
import os
from mininet.log import info, debug
from mininet.term import cleanUpScreens
from mininet.backend import Backend
import pty
import select
import re
from mininet.util import isShellBuiltin
import signal


def sh(cmd):
    "Print a command and send it to the shell"
    info(cmd + '\n')
    process = Popen(['/bin/sh', '-c', cmd], stdout=PIPE)
    return process.communicate()[0]

class Shell(object):
    def __init__(self, inNamespace):
        self.inNamespace = inNamespace
        ( self.pid, self.stdin, self.stdout,
            self.lastPid, self.lastCmd, self.pollOut ) = (
                None, None, None, None, None, None )
        self.waiting = False
        self.readbuf = ''

    def waitReadable(self, timeoutms):
      """Wait until node's output is readable.
        timeoutms: timeout in ms or None to wait indefinitely."""
      if len( self.readbuf ) == 0:
          self.pollOut.poll( timeoutms )

    def monitor(self, timeoutms, findPid):
        """Monitor and return the output of a command.
           Set self.waiting to False if command has completed.
           timeoutms: timeout in ms or None to wait indefinitely."""
        self.waitReadable( timeoutms )
        data = self.read( 1024 )
        # Look for PID
        marker = chr( 1 ) + r'\d+\r\n'
        if findPid and chr( 1 ) in data:
            # Marker can be read in chunks; continue until all of it is read
            while not re.findall( marker, data ):
                data += self.read( 1024 )
            markers = re.findall( marker, data )
            if markers:
                self.lastPid = int( markers[ 0 ][ 1: ] )
                data = re.sub( marker, '', data )
        # Look for sentinel/EOF
        if len( data ) > 0 and data[ -1 ] == chr( 127 ):
            self.waiting = False
            data = data[ :-1 ]
        elif chr( 127 ) in data:
            self.waiting = False
            data = data.replace( chr( 127 ), '' )
        return data


    def execProcess(self, *args, **kwargs):
        """Send a command, followed by a command to echo a sentinel,
           and return without waiting for the command to complete.
           args: command and arguments, or string
           printPid: print command's PID?"""
        assert not self.waiting
        printPid = kwargs.get( 'printPid', True )
        # Allow sendCmd( [ list ] )
        if len( args ) == 1 and type( args[ 0 ] ) is list:
            cmd = args[ 0 ]
        # Allow sendCmd( cmd, arg1, arg2... )
        elif len( args ) > 0:
            cmd = args
        # Convert to string
        if not isinstance( cmd, str ):
            cmd = ' '.join( [ str( c ) for c in cmd ] )
        if not re.search( r'\w', cmd ):
            # Replace empty commands with something harmless
            cmd = 'echo -n'
        self.lastCmd = cmd
        if printPid and not isShellBuiltin( cmd ):
            if len( cmd ) > 0 and cmd[ -1 ] == '&':
                # print ^A{pid}\n so monitor() can set lastPid
                cmd += ' printf "\\001%d\n" $! \n'
            else:
                cmd = 'mnexec -p ' + cmd
        self.write( cmd + '\n' )
        self.lastPid = None
        self.waiting = True

    def waitOutput(self, verbose):
        """Wait for a command to complete.
           Completion is signaled by a sentinel character, ASCII(127)
           appearing in the output stream.  Wait for the sentinel and return
           the output, including trailing newline.
           verbose: print output interactively"""
        log = info if verbose else debug
        output = ''
        while self.waiting:
            data = self.monitor(None, True)
            output += data
            log( data )
        return output

    def terminate(self):
        os.killpg(self.pid, signal.SIGHUP )

    def read(self, maxbytes=1024):
        """Buffered read from node, non-blocking.
           maxbytes: maximum number of bytes to return"""
        count = len( self.readbuf )
        if count < maxbytes:
            data = os.read( self.stdout.fileno(), maxbytes - count )
            self.readbuf += data
        if maxbytes >= len( self.readbuf ):
            result = self.readbuf
            self.readbuf = ''
        else:
            result = self.readbuf[ :maxbytes ]
            self.readbuf = self.readbuf[ maxbytes: ]
        return result

    def readline(self):
        """Buffered readline from node, non-blocking.
           returns: line (minus newline) or None"""
        self.readbuf += self.read( 1024 )
        if '\n' not in self.readbuf:
            return None
        pos = self.readbuf.find( '\n' )
        line = self.readbuf[ 0: pos ]
        self.readbuf = self.readbuf[ pos + 1: ]
        return line

    def write(self, data):
        """Write data to node.
           data: string"""
        os.write( self.stdin.fileno(), data )


    def start(self, name):
       # mnexec: (c)lose descriptors, (d)etach from tty,
        # (p)rint pid, and run in (n)amespace
        opts = '-cd'
        if self.inNamespace:
            opts += 'n'
        # bash -m: enable job control, i: force interactive
        # -s: pass $* to shell, and make process easy to find in ps
        # prompt is set to sentinel chr( 127 )
        os.environ[ 'PS1' ] = chr( 127 )
        cmd = [ 'mnexec', opts, 'bash', '--norc', '-mis', 'mininet:' + name ]
        # Spawn a shell subprocess in a pseudo-tty, to disable buffering
        # in the subprocess and insulate it from signals (e.g. SIGINT)
        # received by the parent
        master, slave = pty.openpty()
        self.shell = Popen( cmd, stdin=slave, stdout=slave, stderr=slave,
                                  close_fds=False )
        self.stdin = os.fdopen( master )
        self.stdout = self.stdin
        self.pid = self.shell.pid
        self.pollOut = select.poll()
        self.pollOut.register( self.stdout )
        # Maintain mapping between file descriptors and nodes
        # This is useful for monitoring multiple nodes
        # using select.poll()
        self.lastCmd = None
        self.lastPid = None
        self.readbuf = ''
        # Wait for prompt
        while True:
            data = self.read( 1024 )
            if data[ -1 ] == chr( 127 ):
                break
            self.pollOut.poll()
        self.waiting = False
        self.execProcess( 'stty -echo' )
        self.waitOutput( False )


class Mnexec(Backend):
    """A class which encapsulate a mininet backend build around the mnexec
    executable. This provides emulation through OS containers and network
    namespaces"""

    def __init__(self):
#        super(self)
        print "Initalising mnexec backend..."
        self.active_shell = dict()

    def cleanup(self):
        """Clean up junk which might be left over from old runs;
           do fast stuff before slow dp and link removal!"""

        info("*** Removing excess controllers/ofprotocols/ofdatapaths/pings/"
             "noxes\n")
        zombies = 'controller ofprotocol ofdatapath ping nox_core lt-nox_core '
        zombies += 'ovs-openflowd ovs-controller udpbwtest mnexec ivs'
        # Note: real zombie processes can't actually be killed, since they
        # are already (un)dead. Then again,
        # you can't connect to them either, so they're mostly harmless.
        # Send SIGTERM first to give processes a chance to shutdown cleanly.
        sh('killall ' + zombies + ' 2> /dev/null')
        time.sleep(1)
        sh('killall -9 ' + zombies + ' 2> /dev/null')

        # And kill off sudo mnexec
        sh('pkill -9 -f "sudo mnexec"')

        info("*** Removing junk from /tmp\n")
        sh('rm -f /tmp/vconn* /tmp/vlogs* /tmp/*.out /tmp/*.log')

        info("*** Removing old X11 tunnels\n")
        cleanUpScreens()

        info("*** Removing excess kernel datapaths\n")
        dps = sh("ps ax | egrep -o 'dp[0-9]+' | sed 's/dp/nl:/'").splitlines()
        for dp in dps:
            if dp:
                sh('dpctl deldp ' + dp)

        info("***  Removing OVS datapaths")
        dps = sh("ovs-vsctl --timeout=1 list-br").strip().splitlines()
        if dps:
            sh("ovs-vsctl " + " -- ".join("--if-exists del-br " + dp
                                          for dp in dps if dp))
        # And in case the above didn't work...
        dps = sh("ovs-vsctl --timeout=1 list-br").strip().splitlines()
        for dp in dps:
            sh('ovs-vsctl del-br ' + dp)

        info("*** Removing all links of the pattern foo-ethX\n")
        links = sh("ip link show | "
                    "egrep -o '([-_.[:alnum:]]+-eth[[:digit:]]+)'").splitlines()
        for link in links:
            if link:
                sh("ip link del " + link)

        info("*** Killing stale mininet node processes\n")
        sh('pkill -9 -f mininet:')
        # Make sure they are gone
        while True:
            try:
                pids = co('pgrep -f mininet:'.split())
            except:
                pids = ''
            if pids:
                sh('pkill -f 9 mininet:')
                time.sleep(.5)
            else:
                break

        info("*** Cleanup complete.\n")

    def startShell(self, inNamespace, name):
        s = Shell(inNamespace)
        self.active_shell[name] = s
        s.start(name )
        return s

    def kill(self, pid, signal):
            os.kill(term.pid, signal.SIGKILL)
