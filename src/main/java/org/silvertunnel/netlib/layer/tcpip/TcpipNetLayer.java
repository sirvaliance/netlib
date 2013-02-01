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

package org.silvertunnel.netlib.layer.tcpip;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;

import org.silvertunnel.netlib.adapter.socket.SocketGlobalUtil;
import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetAddressNameService;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerStatus;
import org.silvertunnel.netlib.api.NetServerSocket;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.impl.PropertiesUtil;
import org.silvertunnel.netlib.api.impl.ServerSocket2NetServerSocket;
import org.silvertunnel.netlib.api.impl.Socket2NetSocket;
import org.silvertunnel.netlib.api.service.NetlibVersion;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.nameservice.cache.CachingNetAddressNameService;
import org.silvertunnel.netlib.nameservice.inetaddressimpl.DefaultIpNetAddressNameService;

/**
 * Plain TCP/IP network layer - uses the JVM default SocketImpl implementation.
 * 
 * Property for createNetServerSocket():
 *   TcpipNetLayer.backlog: integer the maximum length of the server queue (int)
 *
 * @author hapke
 */
public class TcpipNetLayer implements NetLayer {
    public static final String BACKLOG = "TcpipNetLayer.backlog";
    public static final String TIMEOUT_IN_MS = "TcpipNetLayer.timeoutInMs";

    static {
    	// trigger silvertunnel.org Netlib start logging
    	// (we trigger it here because TcpipNetLayer is usually used very early)
    	NetlibVersion.getInstance();
    }
    
    /**
     * the instance of NetAddressNameService;
     * will be initialized during the first call of getNetAddressNameService().
     */
    private NetAddressNameService netAddressNameService;

    public TcpipNetLayer() {
    }
    
    /** @see NetLayer#createNetSocket(Map, NetAddress, NetAddress) */
    public NetSocket createNetSocket(Map<String,Object> localProperties, NetAddress localAddress, NetAddress remoteAddress) throws IOException {
        TcpipNetAddress  r = (TcpipNetAddress)remoteAddress;
        
        // read (optional) properties
        final int TIMEOUT_IN_MS_UNLIMITED = 0;
        Integer timeoutInMs = PropertiesUtil.getAsInteger(localProperties, TIMEOUT_IN_MS, TIMEOUT_IN_MS_UNLIMITED);
        
        // create connection and open socket
        Socket socket = SocketGlobalUtil.createOriginalSocket();
        if (r.getIpaddress()!=null) {
            // use IP address (preferred over host name)
            InetAddress remoteInetAddress = InetAddress.getByAddress(r.getIpaddress());
            InetSocketAddress remoteInetSocketAddress = new InetSocketAddress(remoteInetAddress, r.getPort());
            socket.connect(remoteInetSocketAddress, timeoutInMs);
        } else {
            // use host name
            InetSocketAddress remoteInetSocketAddress = new InetSocketAddress(r.getHostname(), r.getPort());
            socket.connect(remoteInetSocketAddress, timeoutInMs);
        }
        
        // convert and return result
        return new Socket2NetSocket(socket);
    }
    /**
     * Simple version of this method.
     * @see NetLayer#createNetSocket(Map, NetAddress, NetAddress)
     */
    public NetSocket createNetSocket(NetAddress localAddress, NetAddress remoteAddress) throws IOException {
        TcpipNetAddress  r = (TcpipNetAddress)remoteAddress;
        
        // create connection and open socket
        Socket socket;
        if (r.getIpaddress()!=null) {
            // use IP address (preferred over host name)
            InetAddress inetAddress = InetAddress.getByAddress(r.getIpaddress());
            socket = new Socket(inetAddress, r.getPort());
        } else {
            // use host name
            socket = new Socket(r.getHostname(), r.getPort());
        }
        
        // convert and return result
        return new Socket2NetSocket(socket);
    }

    /** @see NetLayer#createNetServerSocket(Map, NetAddress) */
    public NetServerSocket createNetServerSocket(Map<String,Object> properties, NetAddress localListenAddress) throws IOException {
        TcpipNetAddress  l = (TcpipNetAddress)localListenAddress;
        
        // read (optional) properties
        Long backlogL = PropertiesUtil.getAsLong(properties, BACKLOG, null);
        int backlog = (backlogL==null) ? 0 : backlogL.intValue();
        
        // open server socket
        ServerSocket serverSocket = new ServerSocket(l.getPort(), backlog); // TODO: use local address, too
        
        // convert and return result
        return new ServerSocket2NetServerSocket(serverSocket);
    }



    /** @see NetLayer#getStatus() */
    public NetLayerStatus getStatus() {
        return NetLayerStatus.READY;
    }
    
    /** @see NetLayer#waitUntilReady() */
    public void waitUntilReady() {
        // nothing to do
    }

    /** @see NetLayer#clear() */
    public void clear() throws IOException {
        // nothing to do
    }
    
    /** @see NetLayer#getNetAddressNameService */
    public NetAddressNameService getNetAddressNameService() {
        if (netAddressNameService==null) {
            // create a new instance
            netAddressNameService = new CachingNetAddressNameService(new DefaultIpNetAddressNameService());
        }
        
        return netAddressNameService;
    }
}
