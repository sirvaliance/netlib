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

package org.silvertunnel.netlib.layer.modification;

import java.io.IOException;
import java.util.Map;

import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetAddressNameService;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerStatus;
import org.silvertunnel.netlib.api.NetServerSocket;
import org.silvertunnel.netlib.api.NetSocket;

/**
 * Bytewise modification of the input and output stream
 *
 * @author hapke
 */
public class ModificatorNetLayer implements NetLayer {
    private NetLayer lowerNetLayer;
    private ByteModificator inByteModificator;
    private ByteModificator outByteModificator;
    
    public ModificatorNetLayer(NetLayer lowerNetLayer, ByteModificator inByteModificator, ByteModificator outByteModificator) {
        this.lowerNetLayer = lowerNetLayer;
        this.inByteModificator = inByteModificator;
        this.outByteModificator = outByteModificator;
    }
    
    /** @see NetLayer#createNetSocket(Map, NetAddress, NetAddress) */
    public NetSocket createNetSocket(Map<String,Object> localProperties, NetAddress localAddress, NetAddress remoteAddress) throws IOException {
        NetSocket lowerLayerSocket = lowerNetLayer.createNetSocket(localProperties, localAddress, remoteAddress);
        return new ModificatorNetSocket(lowerLayerSocket, inByteModificator, outByteModificator);
    }

    /** @see NetLayer#createNetServerSocket(Map, NetAddress) */
    public NetServerSocket createNetServerSocket(Map<String,Object> properties, NetAddress localListenAddress) {
        throw new UnsupportedOperationException();
    }

    
    
    /** @see NetLayer#getStatus() */
    public NetLayerStatus getStatus() {
        return lowerNetLayer.getStatus();
    }
    
    /** @see NetLayer#waitUntilReady() */
    public void waitUntilReady() {
        lowerNetLayer.waitUntilReady();
    }

    /** @see NetLayer#clear() */
    public void clear() throws IOException {
        lowerNetLayer.clear();
    }
    
    /** @see NetLayer#getNetAddressNameService() */
    public NetAddressNameService getNetAddressNameService() {
        return lowerNetLayer.getNetAddressNameService();
    }
}
