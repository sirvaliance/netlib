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

package org.silvertunnel.netlib.tool;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.impl.InterconnectUtil;

class NetProxySingleConnectionThread extends Thread {
    private static final Logger log = Logger.getLogger(NetProxySingleConnectionThread.class.getName());
    
    private NetSocket upperLayerNetSocket;
    private String lowerNetLayerId;
    
    private static long id;
    
    /**
     * Be a proxy for a single connection.
     * 
     * @param connectionNetSocket    socket of a open connection
     * @param netLayerId             use this NetLayer to forward the data of the connection
     */
    public NetProxySingleConnectionThread(NetSocket upperLayerNetSocket, String lowerNetLayerId) {
        super(createUniqueThreadName());
        this.upperLayerNetSocket = upperLayerNetSocket;
        this.lowerNetLayerId = lowerNetLayerId;
    }

    public void run() {
        try {
            // open lower layer socket
            NetAddress remoteAddress = null;
            NetSocket lowerLayerNetSocket = NetFactory.getInstance().getNetLayerById(lowerNetLayerId).createNetSocket(null, null, remoteAddress);
            
            // interconnect both sockets
            InterconnectUtil.relay(upperLayerNetSocket, lowerLayerNetSocket);
        } catch (Exception e) {
            log.log(Level.WARNING, "connection abborted", e);
        }
    }
    
    /**
     * @return    a new unique name for a thread
     */
    protected static synchronized String createUniqueThreadName() {
        id++;
        return NetProxySingleConnectionThread.class.getName()+id;
    }
}
