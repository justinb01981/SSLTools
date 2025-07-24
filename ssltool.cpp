/* Justin Brady - 6-30-05 
 *a simple proggy that will wait for a connection on a port...
 * when a connection comes in, it tries to negotiate SSL on that connection...
 * if that's successful then open a connection to some other server on some other port,
 * and forward data back and forth. So it bridges an SSL connection to a normal tcp connection
 */
/* this program needs the openssl library. Its found at www.openssl.org */
/* on linux, compile with -lssl */

/*
 * Creating New Keys:
 *   - Private Key
 *     openssl genrsa -out key.pem 2048
 *   - Certificate
 *     openssl req -new -x509 -key key.pem -out cert.pem -days 365
 */

/* usage: ssltool.exe <listen_addr> <listen_port> <remote_host> <remote_port> [server] */

#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include "config.h"

#include "cpthread.h"

#ifdef _BWINDOWS_
#include <winsock.h>
#define SOCKLEN_T int
#define BIT_BUCKET "NUL"
#endif

#ifdef LINUX
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>
#define SOCKET unsigned int
#define SOCKLEN_T socklen_t
#define BIT_BUCKET "/dev/null"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x0
#endif

#endif /* LINUX */

#include <openssl/ssl.h>
#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define TIMEOUT_SECS 600
#define OK 0
#define ERR -1
#define MAX_THREADS 1024

#define CERTF  "./cert.pem"
#define KEYF  "./key.pem"

enum
{
    STATE_UNUSED = 0,
    STATE_CONNECTING,
    STATE_CONNECTED,
    STATE_CLIENT_DISCONNECT,
    STATE_SERVER_DISCONNECT
};

using namespace std;

typedef struct
{
    int state;
    SOCKET sd, sdr, sslsock;
    char buf[/*4096*/18000];
    char sslbuf[/*4096*/18000];
    int buflen, bufoffset, sslbuflen, sslbufoffset;
    struct sockaddr_in sa_remote;
    SSL*    ssl;
    int nossl;
}SecSocketPair;

typedef int (*ssl_funcptr_t)(SSL *);

/* globals */

SSL_CTX* ctx;
X509*    client_cert;
SSL_METHOD *meth;

char gPemFilename[1024];

bool gDone = false;
bool gServerMode = false;
bool gNoSSL = false;

char gRemoteHostName[1024];
unsigned short gRemotePort;
struct sockaddr_in gRemoteSockaddr;

ostream& logstream = cout;
ofstream bit_bucket;

SecSocketPair gSocketPairs[MAX_THREADS];

SOCKET listen_sock;

/* function prototypes */

void ProxyThread(void* params);
void wait_disconnect(int sock, int seconds);
void handle_sigpipe(int p);
int set_nonblocking(SOCKET sock);
void CloseConnection(SecSocketPair *pair);
int do_ssl_write(SSL *ssl, char *buf, int buf_len);
int do_ssl_read(SSL *ssl, char *buf, int buf_len);
int do_write(int sock, char *buf, int buf_len);
int do_read(int sock, char *buf, int buf_len);

#ifdef _BWINDOWS_
int close(SOCKET s)
{
    return closesocket(s);
}
#endif /* _BWINDOWS_ */

int MyInitSSL()
{
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    meth = (gServerMode ?
            SSLv23_server_method() :
            SSLv23_client_method());
    ctx = SSL_CTX_new (meth);
    if (!ctx)
    {
        cout << "SSL_CTX_new failed" << endl;
        //ERR_print_errors_fp(stderr);
        return ERR;
    }

    if(gServerMode)
    {
        //if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
        if (SSL_CTX_use_certificate_chain_file(ctx, CERTF) <= 0)
        {
            logstream << "SSL_CTX_use_certificate_file failed" << endl;
            cout << "couldn't find certificate ("
                 << CERTF << ")" << endl;
            return ERR;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
        {
            logstream << "SSL_CTX_use_PrivateKey_file failed" << endl;
            cout << "couldn't find key file ("
                 << KEYF << ")" << endl;
            return ERR;
        }
        if (!SSL_CTX_check_private_key(ctx))
        {
            logstream << "Private key does not match the certificate "
                      << "public key" << endl;
            return ERR;
        }
    }

    return OK;
}

int main(int argc, char** argv)
{
    SOCKET listen_sd;
    SOCKET sd, sdr;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;
    unsigned int client_len;
    int err;
    CPThread *workerThread;
    struct hostent *host;
    int argn = 1;
    int debug = 0;

    memset(gSocketPairs, 0, sizeof(gSocketPairs));

#ifdef LINUX
    signal(SIGPIPE, handle_sigpipe);
#endif

    if(argc < 5)
    {
        cout << "usage: ssltool <listen_ssl_addr> <listen_ssl_port> "
             << "<remote_host> <remote_port> [-s] [server] [-n] [-d]" << "\n"
             << "\texamples:\n\tssltool 0.0.0.0 445 127.0.0.1 80 -s (runs server)\n"
             << "\tssltool 0.0.0.0 8443 1.2.3.4 443 (runs client listening on 8443)\n"
             << "\tssltool 0.0.0.0 8443 1.2.3.4 443 -n (runs client listening on 8443 (no ssl, tcp only))\n";
        return 0;
    }

    char *localAddr = argv[argn++];
    char *localPort = argv[argn++];
    strcpy(gRemoteHostName, argv[argn++]);
    gRemotePort = atoi(argv[argn++]);

    while(argn < argc)
    {
        if(!strcmp(argv[argn], "server") || !strcmp(argv[argn], "-s"))
        {
            gServerMode = true;
        }

        if(!strcmp(argv[argn], "-n"))
        {
            gNoSSL = true;
        }

        if(!strcmp(argv[argn], "-d"))
        {
            debug = 1;
        }
        argn++;
    }

    if(!debug)
    {
        bit_bucket.open(BIT_BUCKET, ios::out);
        logstream.rdbuf(bit_bucket.rdbuf());
    }

    if(MyInitSSL() != OK)
    {
        logstream << "MyInitSSL() failed..." << endl;
        return 0;
    }
    
    /* todo: spawn a thread to re-resolve the IP for hostname */
    host = gethostbyname(gRemoteHostName);
    if(!host)
    {
        logstream << "gethostbyname failed (" << gRemoteHostName << ")" << endl;
        return 0;
    }
    memcpy(&gRemoteSockaddr.sin_addr.s_addr, host->h_addr_list[0],
           sizeof(struct in_addr));
    gRemoteSockaddr.sin_port = htons(gRemotePort);
    gRemoteSockaddr.sin_family = AF_INET;

#ifdef _BWINDOWS_
    WSADATA wsadata;
    WSAStartup(0x202, &wsadata);
#endif /* _BWINDOWS_ */

    /* open listen socket */
    listen_sd = socket (AF_INET, SOCK_STREAM, 0);

    if(set_nonblocking(listen_sd) != 0) return 0;

    memset(&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    /*
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    */
    sa_serv.sin_addr.s_addr = inet_addr(localAddr);
    sa_serv.sin_port        = htons (atoi(localPort));          /* Server Port number */

    err = bind(listen_sd, (struct sockaddr*) &sa_serv, sizeof (sa_serv));
    if(err == -1)
    {
        logstream << "bind failed" << endl;
        return 0;
    }
    listen_sock = listen_sd;

    /* start worker-thread */
    workerThread = new CPThread((void *)ProxyThread, (void *)NULL);
    if(!workerThread)
    {
        logstream << "thread init failed" << endl;
        return 0;
    }
    workerThread->start();

    /* wait for a connection */
    err = listen(listen_sd, MAX_THREADS);
    if(err == -1)
    {
        logstream << "listen failed" << endl;
        return 0;
    }

    while(!gDone)
    {
        sleep(1);
    }

    SSL_CTX_free (ctx);

    close (listen_sd);

    delete workerThread;

    return 0;
}

int AcceptConnection()
{
    unsigned int client_len;
    int i;
    SOCKET sd;
    struct sockaddr_in sa_cli;
    SecSocketPair *sockpair = gSocketPairs;

    client_len = sizeof(sa_cli);
    sd = accept(listen_sock, (struct sockaddr*) &sa_cli, 
                (SOCKLEN_T*) &client_len);

    if(sd == -1)
        return -1;

    /* find empty slot */
    while(sockpair < (gSocketPairs + sizeof(gSocketPairs)))
    {
        if(sockpair->state == STATE_UNUSED) break;
        sockpair++;
    }

    if(sockpair > (gSocketPairs + sizeof(gSocketPairs)))
    {
        logstream << "MAX_CONNECTIONS reached" << endl;
        close(sd);
        return -1;
    }

    memset(sockpair, 0, sizeof(*sockpair));
    sockpair->sd = sd;
    sockpair->state = STATE_CONNECTING;

    return 0;
} 

int SetupConnection(SecSocketPair *s)
{
    int err = 0;
    hostent host;
    ssl_funcptr_t ssl_setup_func;

    ssl_setup_func = (gServerMode? SSL_accept: SSL_connect);

    s->nossl = 0;
    
    do {    
        s->sdr = socket(AF_INET, SOCK_STREAM, 0);
        if(s->sdr == -1)
        {
            err = 1;
            break;
        }

        struct sockaddr_in *cxnAddr = &gRemoteSockaddr;

        err = connect(s->sdr, (sockaddr*) cxnAddr,
                      sizeof(struct sockaddr_in));
        if(err == -1)
        {
            err = 1;
            logstream << "connect failed" << endl;
            break;
        }

        if(set_nonblocking(s->sd) != 0
           || set_nonblocking(s->sdr) != 0)
        {
            err = 1;
            logstream << "set non-blocking failed: "
                      << strerror(errno) << endl;
            break;
        }

        logstream << "connect() from " << inet_ntoa(cxnAddr->sin_addr) <<":"<< ntohs(cxnAddr->sin_port) << endl;

        logstream << "calling SSL_new..." << endl;
        s->ssl = SSL_new(ctx);
        if(!s->ssl)
        {
            logstream << "SSL_new failed" << endl;
            err = 1;
            break;
        }

        s->sslsock = (gServerMode? s->sd: s->sdr);
        SSL_set_fd(s->ssl, s->sslsock);

        s->nossl = gNoSSL;

        logstream << "calling ssl_setup_func...";
        if (s->nossl)
        {
            err = 1;
        }
        else
        {
            err = (*ssl_setup_func)(s->ssl);
        }

        if(err <= 0)
        {
            int failed = 0;
            /*
            while(1)
            */
            do
            {
                int serr = SSL_get_error(s->ssl, err);
                if(serr > 0)
                {
                    err = 0;
                    break;
                }

                if(serr == SSL_ERROR_WANT_READ
                   || serr == SSL_ERROR_WANT_WRITE)
                {
                    /* supposed to call select() to wait for handshake */
                    if( (err = (*ssl_setup_func)(s->ssl)) > 0)
                    {
                        err = 0;
                        break;
                    }
                }
                else
                {
                    logstream << "failed" << endl;
                    failed = 1;       
                    break;
                }
            } while(0);

            if(failed)
            {
                logstream << "SSL_connect/accept failed: " 
                          << SSL_get_error(s->ssl, err)
                          << " errno: " << errno
                          << endl;
                err = 1;
                break;
            }
            else
            {
                struct sockaddr_in cxnAddr;
                socklen_t caLen = sizeof(cxnAddr);

                if(getpeername(s->sd, (struct sockaddr*) &cxnAddr, &caLen) == 0) {
                    logstream << "connected " << inet_ntoa(cxnAddr.sin_addr) <<":"<< ntohs(cxnAddr.sin_port) << endl;
                    err = 0;
                }
            }
        }
    }while(0);

    if(err == 0)
    {
        /* set state as "proxying" */
        if(gServerMode)
        {
            SOCKET tmp = s->sd;
            s->sd = s->sdr;
            s->sdr = tmp;
        }
    }
    else
    {
        if(s->sd) close(s->sd);
        if(s->sdr) close(s->sdr);
        if(s->ssl) SSL_free(s->ssl);
        s->ssl = NULL;
        s->sd = 0;
        s->sdr = 0;
    }

    return err;
}

void ProxyThread(void *params)
{
    int i, max, err, buffers_pending;
    int flags = 0;
    fd_set rdset;
    struct timeval timeout;
    SecSocketPair *s;

    logstream << "ProxyThead starting" << endl;

    while(!gDone)
    {
#ifdef LINUX
        flags |= MSG_NOSIGNAL;
#endif
        
        FD_ZERO(&rdset);
        FD_SET(listen_sock, &rdset);
        max = listen_sock;
        i = 0;
        buffers_pending = 0;
        while(i < MAX_THREADS)
        {
            s = &gSocketPairs[i];

            if(s->state == STATE_CONNECTING)
            {
                logstream << "new connection request..." << endl;
                if(SetupConnection(s) == 0)
                {
                    logstream << "new connection established" << endl;
                    s->state = STATE_CONNECTED;
                }
                else
                {
                    logstream << "SetupConnection failed" << endl;
                    s->state = STATE_UNUSED;
                }
            }

            if(s->state == STATE_CONNECTED)
            {
                if(s->sd > max) max = s->sd;
                if(s->sdr > max) max = s->sdr;

                FD_SET(s->sd, &rdset);
                FD_SET(s->sdr, &rdset);
    
                if(s->buflen > 0 || s->sslbuflen > 0) buffers_pending = 1;
            }
            else if(s->state == STATE_CLIENT_DISCONNECT
                    || s->state == STATE_SERVER_DISCONNECT)
            {
                logstream << "connection closing..." << endl;
                CloseConnection(s);
            }
            i++;
        }
       
        timeout.tv_sec = 0;
        timeout.tv_usec = (buffers_pending? 1000: 1000000);
        logstream << "ProxyThread: entering select()...";
        if(select(max+1, &rdset, NULL, NULL, buffers_pending? &timeout: NULL) < 0)
        {
            logstream << "select < 0" << endl;
            break;
        }
        logstream << "done" << endl;

        if(FD_ISSET(listen_sock, &rdset))
        {
            AcceptConnection();
        }
        
        i = 0;
        while(i < MAX_THREADS)
        {
            int r, w, written = 0;
            char buf[4096];
            s = &gSocketPairs[i];

            if(s->state == STATE_CONNECTED)
            {
                if(FD_ISSET(s->sd, &rdset) && s->buflen == 0)
                {
                    r = recv(s->sd, s->buf, sizeof(s->buf), flags);
                    if(r <= 0)
                    {
                        s->state = STATE_CLIENT_DISCONNECT;
                        break;
                    }
                    s->buflen = r;
                }

                if(s->buflen > 0)
                {
                    while(s->bufoffset < s->buflen)
                    {
                        if (s->nossl)
                        {
                            w = do_write(s->sslsock,
                                         s->buf + s->bufoffset,
                                         s->buflen - s->bufoffset);
                        }
                        else
                        {
                            w = do_ssl_write(s->ssl,
                                             s->buf + s->bufoffset,
                                             s->buflen - s->bufoffset);
                        }
                        if(w == 0) break;
                        if(w < 0)
                        {
                            logstream << "do_ssl_write failed" << endl;
                            s->state =
                                STATE_SERVER_DISCONNECT;
                            break;
                        }
                        s->bufoffset += w;
                    }

                    /* completely flushed */
                    if(s->bufoffset >= s->buflen)
                    {
                        s->buflen = 0;
                        s->bufoffset = 0;
                    }
                }

                if(FD_ISSET(s->sdr, &rdset) && s->sslbuflen == 0)
                {
                    if(s->nossl)
                    {
                        r = do_read(s->sslsock, s->sslbuf, sizeof(s->sslbuf));
                    }
                    else
                    {
                        r = do_ssl_read(s->ssl, s->sslbuf, sizeof(s->sslbuf));
                    }

                    if(r < 0)
                    {
                        logstream << "do_ssl_read failed" << endl;
                        s->state = STATE_SERVER_DISCONNECT;
                        break;
                    }
                    s->sslbuflen = r;
                }

                if(s->sslbuflen > 0)
                {
                    while(s->sslbufoffset < s->sslbuflen)
                    {
                        w = do_write(s->sd,
                                     s->sslbuf + s->sslbufoffset,
                                     s->sslbuflen - s->sslbufoffset);
                        if(w == 0) break;
                        if(w < 0)
                        {
                            s->state = STATE_CLIENT_DISCONNECT;
                            break;
                        }
                        s->sslbufoffset += w;
                    }
                    
                    /* completely flushed */
                    if(s->sslbufoffset >= s->sslbuflen)
                    {
                        s->sslbuflen = 0;
                        s->sslbufoffset = 0;
                    }
                }
            }
            i++;
        }
    }
}

/* returns:  < 0 = connection lost, 0 = try again later, >0 = # read */
int do_ssl_read(SSL *ssl, char *buf, int buf_len)
{
    int err = 0, r;
    r = SSL_read(ssl, buf, buf_len);
    if(r > 0)
    {
        return r;
    }
    else if(r == 0)
    {
        return -1;
    }
    else
    {
        err = SSL_get_error(ssl, r);
        if(err == SSL_ERROR_WANT_READ
           || err == SSL_ERROR_WANT_WRITE)
        {
            /* try again */
            return 0;
        }
        else
        {
            return -1;   
        }
    }
    return -1;
}

/* returns:  < 0 = connection lost, 0 = try again later, >0 = # written */
int do_ssl_write(SSL *ssl, char *buf, int buf_len)
{
    int err = 0, r;
    r = SSL_write(ssl, buf, buf_len);
    if(r > 0)
    {
        return r;
    }
    else if(r == 0)
    {
        return -1;
    }
    else
    {
        err = SSL_get_error(ssl, r);
        if(err == SSL_ERROR_WANT_READ
           || err == SSL_ERROR_WANT_WRITE)
        {
            /* try again */
            return 0;
        }
        else
        {
            return -1;   
        }
    }
    return -1;
}

int do_write(int sock, char *buf, int buf_len)
{
    int r;
    int flags = 0;

#ifdef LINUX
    flags |= MSG_NOSIGNAL;
#endif
    errno = 0;
    r = send(sock, buf, buf_len, flags);
    if(r == 0)
    {
        return -1;
    }
    else if(r == -1)
    {
        if(errno == EAGAIN
           || errno == EWOULDBLOCK
           || errno == EINTR)
        {
            return 0;
        }
    }
    else
    {
        return r;
    }
}

int do_read(int sock, char *buf, int buf_len)
{
    int r;
    int flags = 0;

#ifdef LINUX
    flags |= MSG_NOSIGNAL;
#endif
    errno = 0;
    r = recv(sock, buf, buf_len, flags);
    if(r == 0)
    {
        return -1;
    }
    else if(r == -1)
    {
        if(errno == EAGAIN
           || errno == EWOULDBLOCK
           || errno == EINTR)
        {
            return 0;
        }
    }
    else
    {
        return r;
    }
}

void CloseConnection(SecSocketPair *pair)
{
    if(pair->buflen > 0)
    {
	logstream << "WARN: closing connection with buflen > 0" << endl;
    }
    if(pair->sslbuflen > 0)
    {
        logstream << "WARN: closing connection with sslbuflen > 0" << endl;
    }
    close(pair->sd);
    SSL_shutdown(pair->ssl);
    SSL_free(pair->ssl);
    close(pair->sdr);
    pair->state = STATE_UNUSED;
}

void handle_sigpipe(int p)
{
}

int set_nonblocking(SOCKET sock)
{
    long v;
    int flags;
    v = 1;
    /*
    if(setsockopt(sock, SOL_SOCKET, O_NONBLOCK, &v, sizeof(v))
       != 0)
    {
        return -1;
    }
    */
    flags = fcntl(sock, F_GETFL, 0);
    if(flags == -1) flags = 0;

    if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) != 0)
    {
        return -1;
    }
    return 0;
}
