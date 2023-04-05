using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EasyTCPeasy.Network.Server
{
    public class EasyTCPServer
    {
        public IPAddress Address { get; private set; }
        public int Port { get; private set; }
        public bool SslEnabled { get; private set; }

        private TcpListener _listener;
        private X509Certificate2 _sslCertificate;

        private CancellationToken _stopToken;
        private CancellationTokenSource _stopTokenSrc;

        public EasyTCPServer(IPAddress ipAddress, int port)
        {
            Address = ipAddress;
            Port = port;

            _listener = new TcpListener(this.Address, this.Port);

            _stopTokenSrc = new CancellationTokenSource();
            _stopToken = _stopTokenSrc.Token;
        }

        private async Task<X509Certificate2> GetSslCertificateAsync(string certificate, StoreName storeName, StoreLocation storeLoc, OpenFlags openFlags, bool verifyCert)
        {
            return await Task.Run(() =>
            {
                var store = new X509Store(storeName, storeLoc, openFlags);
                store.Open(openFlags);

                var certificates = store.Certificates.Find(X509FindType.FindBySubjectName, certificate, validOnly: verifyCert);

                if(certificates.Count < 1)
                {
                    throw new Exception("No Ssl Certificate was found in the X509Store.");
                }

                return certificates.First();
            });
        }

        public async Task InitializeSslAsync(string certificate, StoreName storeName = StoreName.My, StoreLocation storeLoc = StoreLocation.CurrentUser, OpenFlags openFlags = OpenFlags.ReadOnly, bool verifyCert = false)
        {
            _sslCertificate = await GetSslCertificateAsync(certificate, storeName, storeLoc, openFlags, verifyCert);
            SslEnabled = true;
        }

        public async Task StartAsync()
        {
            _listener.Start();

            while (!_stopToken.IsCancellationRequested)
            {
                var tcpClient = await _listener.AcceptTcpClientAsync();

                HandleClientConnectAsync(tcpClient);
            }
        }

        public async Task StopAsync()
        {
            await Task.Run(() =>
            {
                // TODO: Kick all clients.

                _stopTokenSrc.Cancel();
                _listener.Stop();
            });
        }

        private async Task HandleClientConnectAsync(TcpClient client)
        {
            var easyClient = new EasyTCPClient()
            {
                Client = client,
                SslEnabled = true
            };

            if(SslEnabled)
            {
                await SSLHandshakeAsync(easyClient.GetStream());
            }
        }

        private async Task SSLHandshakeAsync(Stream stream)
        {
            if(stream == null)
            {
                throw new ArgumentNullException("Stream is null.");
            }

            if (stream is not SslStream)
            {
                throw new ArgumentException("Stream is not SslStream.");
            }

            if (_sslCertificate == null)
            {
                throw new NullReferenceException("SSLCertificate is null.");
            }

            SslStream? _sslStream = stream as SslStream;

            if(_sslStream == null)
            {
                throw new NullReferenceException("SslStream was null.");
            }

            await _sslStream.AuthenticateAsServerAsync(
                    serverCertificate: _sslCertificate,
                    clientCertificateRequired: false,
                    enabledSslProtocols: SslProtocols.None,
                    checkCertificateRevocation: true);

            _sslStream.ReadTimeout = 5000;
            _sslStream.WriteTimeout = 5000;
        }
    }
}
