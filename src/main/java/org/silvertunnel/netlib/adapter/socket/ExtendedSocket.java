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

package org.silvertunnel.netlib.adapter.socket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;

import org.silvertunnel.netlib.api.NetSocket;

/**
 * This class is the same as java.net.Socket but with an additional public constructor.
 * See class SocketUtil.
 * 
 * In addition it implements the org.silvertunnel.netlib.api.NetSocket interface.
 * This is used to unify handling of Sockets and NetSockets.
 * Hint: the connection must be established before an instance of this
 *       class can be used as NetSocket.
 * 
 * @author hapke
 */
public class ExtendedSocket extends Socket implements NetSocket {

    ///////////////////////////////////////////////////////
    // constructor from java.net.Socket
    ///////////////////////////////////////////////////////

    public ExtendedSocket() {
        super();
    }

    public ExtendedSocket(Proxy proxy) {
        super(proxy);
    }
    public ExtendedSocket(String host, int port) throws IOException {
        super(host, port);
    }

    public ExtendedSocket(InetAddress address, int port) throws IOException {
        super(address, port);
    }

    public ExtendedSocket(String host, int port, InetAddress localAddr,
            int localPort) throws IOException {
        super(host, port, localAddr, localPort);
    }

    public ExtendedSocket(InetAddress address, int port, InetAddress localAddr,
            int localPort) throws IOException {
        super(address, port, localAddr, localPort);
    }

    ///////////////////////////////////////////////////////
    // additional public constructor
    ///////////////////////////////////////////////////////
    
    /**
     * @param socketImpl
     * @throws SocketException
     */
    public ExtendedSocket(SocketImpl socketImpl) throws SocketException {
        super(socketImpl);
    }
}
