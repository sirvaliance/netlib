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

package org.silvertunnel.netlib.layer.control;

import java.io.IOException;
import java.util.Map;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetAddressNameService;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerStatus;
import org.silvertunnel.netlib.api.NetServerSocket;
import org.silvertunnel.netlib.api.NetSocket;

/**
 * Transparent NetLayer that enforces time(out) and throughput limits
 * of a wrapped NetLayer. 
 * It aborts connections that hits the configured limits.
 * 
 * @author hapke
 */
public class ControlNetLayer implements NetLayer {
    private static Logger log = Logger.getLogger(ControlNetLayer.class.getName());

    private NetLayer lowerNetLayer;
    private ControlParameters controlParameters;
    
    
    /**
     * Initialize a new layer.
     * 
     * @param lowerNetLayer
     * @param controlParameters    definition when to terminate a connection 
     */
    public ControlNetLayer(NetLayer lowerNetLayer, ControlParameters controlParameters) {
        this.lowerNetLayer = lowerNetLayer;
        this.controlParameters = controlParameters;
    }
    
    /** @see NetLayer#createNetSocket(Map, NetAddress, NetAddress) */
    public NetSocket createNetSocket(Map<String,Object> localProperties, NetAddress localAddress, NetAddress remoteAddress) throws IOException {
        return new ControlNetSocket(
                lowerNetLayer.createNetSocket(localProperties, localAddress, remoteAddress),
                controlParameters);
    }

    /** @see NetLayer#createNetServerSocket(Map, NetAddress) */
    public NetServerSocket createNetServerSocket(Map<String,Object> properties, NetAddress localListenAddress) throws IOException {
        throw new UnsupportedOperationException();
    }

    public void clear() throws IOException {
        lowerNetLayer.clear();
    }

    public NetAddressNameService getNetAddressNameService() {
        return lowerNetLayer.getNetAddressNameService();
    }

    public NetLayerStatus getStatus() {
        return lowerNetLayer.getStatus();
    }

    public void waitUntilReady() {
        lowerNetLayer.waitUntilReady();
    }
}
