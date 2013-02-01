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

package org.silvertunnel.netlib.layer.tor;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerFactory;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.layer.socks.SocksServerNetLayer;
import org.silvertunnel.netlib.util.TempfileStringStorage;

/**
 * Factory used to manage the default instance of the
 * TorNetLayer.
 * This factory will be instantiated via default constructor.
 * 
 * Needed only by convenience-class NetFactory.
 * 
 * @author hapke
 */
public class TorNetLayerFactory implements NetLayerFactory {
    private static final Logger log = Logger.getLogger(TorNetLayerFactory.class.getName());

    private NetLayer torNetLayer;
    private NetLayer socksOverTorNetLayer;

    /**
     * @see NetLayerFactory#getNetLayerById(String)
     * 
     * @param netLayerId
     * @return the requested NetLayer if found; null if not found;
     *         it is not guaranteed that the type is TorNetLayer
     */
    public synchronized NetLayer getNetLayerById(String netLayerId) {
        try {
            if (NetLayerIDs.TOR_OVER_TLS_OVER_TCPIP.equals(netLayerId)) {
                if (torNetLayer==null) {
                    // create a new netLayer instance
                    NetLayer tcpipNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP);
                    NetLayer tlsNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TLS_OVER_TCPIP);
    
                    torNetLayer = new TorNetLayer(tlsNetLayer, tcpipNetLayer, TempfileStringStorage.getInstance());
                }
                return torNetLayer;

            } else if (NetLayerIDs.SOCKS_OVER_TOR_OVER_TLS_OVER_TCPIP.equals(netLayerId)) {
                if (socksOverTorNetLayer==null) {
                    // create a new netLayer instance
                    if (torNetLayer==null) {
                        // fill torNetLayer first
                        torNetLayer = getNetLayerById(NetLayerIDs.TOR_OVER_TLS_OVER_TCPIP);
                    }
                    
                    socksOverTorNetLayer = new SocksServerNetLayer(torNetLayer);
                }
                return socksOverTorNetLayer;
            }

            // unsupported netLayerId
            return null;

        } catch (Exception e) {
            log.log(Level.SEVERE, "could not create "+netLayerId, e);
            return null;
        }
    }
}
