/**
 * OnionCoffee - Anonymous Communication through TOR Network
 * Copyright (C) 2005-2007 RWTH Aachen University, Informatik IV
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
package org.silvertunnel.netlib.layer.tor.serverimpl;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Map;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

import org.silvertunnel.netlib.layer.tor.api.Fingerprint;
import org.silvertunnel.netlib.layer.tor.circuit.TLSConnection;
import org.silvertunnel.netlib.layer.tor.clientimpl.Tor;
import org.silvertunnel.netlib.layer.tor.common.TorX509TrustManager;

/**
 * main class for Tor server functionality
 * 
 * @author Lexi Pimenidis
 */
class ServerMain {
    private static final Logger log = Logger.getLogger(ServerMain.class.getName());
 
    private static final String[] enabledSuites = { "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" };
    private static final String filenameKeyStore = "/tmp";

    private Tor tor;
    private Thread orListener;
    private SSLServerSocket orServer;
    /** reference to tls-connections in FirstNodeHandler!! */
    private Map<Fingerprint,TLSConnection> tlsConnectionMap; 

 
    /**
     * creates the TLS server socket and installs a dispatcher for incoming
     * data.
     * 
     * @param orPort
     *            the port to open for or-connections
     * @param dirPort
     *            the port to open for directory services
     * @exception IOException
     * @exception SSLPeerUnverifiedException
     */
    ServerMain(Tor tor, int orPort, int dirPort) throws IOException, SSLPeerUnverifiedException, SSLException {
        this.tor = tor;
            
        if (orPort < 1) {
            throw new IOException("invalid port given");
        }
        if (dirPort < 1) {
            throw new IOException("invalid port given");
        }
        if (orPort > 0xffff) {
            throw new IOException("invalid port given");
        }
        if (dirPort > 0xffff) {
            throw new IOException("invalid port given");
        }

        //tlsConnectionMap = tor.getTlsConnectionAdmin().getConnectionMap();
        KeyManager kms[] = new KeyManager[1];
        kms[0] = tor.getPrivateKeyHandler();

        // use the keys and certs from above to connect to Tor-network
        try {
            TrustManager[] tms = { new TorX509TrustManager() };
            SSLContext context = SSLContext.getInstance("TLS", "SunJSSE");
            context.init(kms, tms, null);
            SSLServerSocketFactory factory = (SSLServerSocketFactory) context.getServerSocketFactory();

            orServer = (SSLServerSocket) factory.createServerSocket(orPort);

            // FIXME: check certificates received in TLS

            /*
             * // for debugging purposes
             * javax.net.ssl.HandshakeCompletedListener hscl = new
             * javax.net.ssl.HandshakeCompletedListener() { public void
             * handshakeCompleted(HandshakeCompletedEvent e) { try {
             * log.info("Cipher: "+e.getCipherSuite());
             * java.security.cert.Certificate[] chain =
             * e.getLocalCertificates(); log.info("Send cert-chain of
             * length "+chain.length); for(int i=0;i<chain.length;++i)
             * log.info(" cert "+i+": "+chain[i].toString()); chain =
             * e.getPeerCertificates(); log.info("Recieved cert-chain
             * of length "+chain.length); for(int i=0;i<chain.length;++i)
             * log.info(" cert "+i+": "+chain[i].toString()); }
             * catch(Exception ex) {} } };
             * tls.addHandshakeCompletedListener(hscl);
             */
            orServer.setEnabledCipherSuites(enabledSuites);

            // start listening for incoming data
            orListener = new Thread() {
                public void run() {
                    try {
                        while (true) {
                            try {
                                SSLSocket ssl = (SSLSocket) (orServer.accept());
                                ssl.setEnabledCipherSuites(enabledSuites);
                                ssl.startHandshake();
                                TLSConnection tls = null; // TODO: new TLSConnection(ssl);
                                // add connection to array
                                String descr = ssl.getInetAddress().getHostAddress() + ":" + ssl.getPort();
                                log.fine("Incoming TLS connection from " + descr);
                                throw new RuntimeException("currently not implemented correctly");
                                //tlsConnectionMap.put(descr, tls);
                            } catch (SecurityException e) {
                            }
                        }
                    } catch (IOException e) {
                    }
                }
            };
            orListener.start();

        } catch (NoSuchProviderException e) {
            SSLException e2 = new SSLException(e.getMessage());
            e2.setStackTrace(e.getStackTrace());
            throw e2;
        } catch (NoSuchAlgorithmException e) {
            SSLException e2 = new SSLException(e.getMessage());
            e2.setStackTrace(e.getStackTrace());
            throw e2;
        } catch (KeyManagementException e) {
            SSLException e2 = new SSLException(e.getMessage());
            e2.setStackTrace(e.getStackTrace());
            throw e2;
        }
    }

    /**
     * @param force
     *            set to TRUE if close anyway as fast as possible
     */
    void close(boolean force) {
        log.fine("ServerMain.close(): Closing TLS server");

        // tls-connections are handled by FirstNodeHandler, no need to close
        // form here and there
        // close connections
        try {
            orServer.close();
        } catch (IOException e) {
        }
        // join thread listening on server port
        try {
            orListener.join();
        } catch (InterruptedException e) {
        }
    }
}
