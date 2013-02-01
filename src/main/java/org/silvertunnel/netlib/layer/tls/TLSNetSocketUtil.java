/*
 * silvertunnel.org Netlib - Java library to easily access anonymity networks
 * Copyright (c) 2009-2012 silvertunnel.org
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

package org.silvertunnel.netlib.layer.tls;

import java.io.IOException;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.impl.NetSocket2Socket;
import org.silvertunnel.netlib.api.impl.Socket2NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;


/**
 * Helper method to access the Java-internal TLS/SSL logic.
 *  
 * @author hapke
 */
public class TLSNetSocketUtil {
    private static final Logger log = Logger.getLogger(TLSNetSocketUtil.class.getName());

    /**
     * Returns a socket layered over an existing socket connected to the named host, at the given port.
     * This construction can be used when tunneling SSL/TLS through a proxy or when negotiating the use of SSL/TLS over an existing socket.
     * The host and port refer to the logical peer destination.
     * 
     * @param lowerLayerNetSocket
     * @param remoteAddress
     * @param autoClose
     * @param enabledCipherSuites    if null, the default TLS cipher suites are used
     * @param keyManagers            if null, the now local keys are used
     * @param trustManagers          if null, the default trust managers are used
     * @return
     * @throws IOException
     */
    public static NetSocket createTLSSocket(NetSocket lowerLayerNetSocket, TcpipNetAddress remoteAddress,
            boolean autoClose,
            String[] enabledCipherSuites,
            KeyManager[] keyManagers,
            TrustManager[] trustManagers) throws IOException {
        Socket lowerLayerSocket = new NetSocket2Socket(lowerLayerNetSocket);

        // create  TLS/SSL socket factory
        SSLContext context = null;
        try {
            context = SSLContext.getInstance("TLS", "SunJSSE");
            context.init(keyManagers, trustManagers, null);
        } catch (NoSuchAlgorithmException e) {
            IOException ioe = new IOException();
            ioe.initCause(e);
            throw ioe;
        } catch (KeyManagementException e) {
            IOException ioe = new IOException();
            ioe.initCause(e);
            throw ioe;
        } catch (NoSuchProviderException e) {
            IOException ioe = new IOException();
            ioe.initCause(e);
            throw ioe;
        }
        SSLSocketFactory f = (SSLSocketFactory) context.getSocketFactory();

        // create TLS/SSL session with socket
        String hostname = (remoteAddress!=null) ? remoteAddress.getHostname() : null;
        int port = (remoteAddress!=null) ? remoteAddress.getPort() : 0;
        SSLSocket resultSocket = (SSLSocket)f.createSocket(lowerLayerSocket, hostname, port, autoClose);
        
        // set properties
        log.finer("default enabledCipherSuites="+Arrays.toString(resultSocket.getEnabledCipherSuites()));
        if (enabledCipherSuites!=null) {
            resultSocket.setEnabledCipherSuites(enabledCipherSuites);
            log.fine("set enabledCipherSuites="+Arrays.toString(enabledCipherSuites));
        }
        
        return new TLSNetSocket(new Socket2NetSocket(resultSocket), resultSocket.getSession(), ""+lowerLayerNetSocket);
    }
}
