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
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetAddressNameService;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerStatus;
import org.silvertunnel.netlib.api.NetServerSocket;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.impl.PropertiesUtil;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;

/**
 * TLS/SSL transport layer protocol implementation.
 * 
 * Supported localProperties:
 * TLSNetLayer.enabledCipherSuites=TLS_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,...
 * 
 * @author hapke
 */
public class TLSNetLayer implements NetLayer {
    public static final String ENABLES_CIPHER_SUITES = "TLSNetLayer.enabledCipherSuites";
    public static final String KEY_MANAGERS = "TLSNetLayer.KEYManagers";
    public static final String TRUST_MANAGERS = "TLSNetLayer.TrustManagers";
    
    private NetLayer lowerNetLayer;
    
    public TLSNetLayer(NetLayer lowerNetLayer) {
        this.lowerNetLayer = lowerNetLayer;
    }
    
    /** @see NetLayer#createNetSocket(Map, NetAddress, NetAddress) */
    public NetSocket createNetSocket(Map<String,Object> localProperties, NetAddress localAddress, NetAddress remoteAddress) throws IOException {
        // create lower layer socket
        Map<String,Object> lowerLayerProperties = null;
        if (localProperties!=null) {
            lowerLayerProperties = new HashMap<String,Object>(localProperties);
            lowerLayerProperties.remove(ENABLES_CIPHER_SUITES);
            lowerLayerProperties.remove(KEY_MANAGERS);
            lowerLayerProperties.remove(TRUST_MANAGERS);
        }
        NetSocket lowerLayerSocket = lowerNetLayer.createNetSocket(
                lowerLayerProperties, localAddress, remoteAddress);
        
        // read (optional) properties
        String[] enabledCipherSuites = PropertiesUtil.
            getAsStringArray(localProperties, ENABLES_CIPHER_SUITES, null);
        
        Object keyManagersObj = PropertiesUtil.
            getAsObject(localProperties, KEY_MANAGERS, null);
        KeyManager[] keyManagers = null;
        if ((keyManagersObj!=null) && (keyManagersObj instanceof KeyManager[])) {
            keyManagers = (KeyManager[])keyManagersObj;
        }

        Object trustManagersObj = PropertiesUtil.
            getAsObject(localProperties, TRUST_MANAGERS, null);
        TrustManager[] trustManagers = null;
        if ((trustManagersObj!=null) && (trustManagersObj instanceof TrustManager[])) {
            trustManagers = (TrustManager[])trustManagersObj;
        }
        
        // create TLS/SSL session
        final boolean AUTO_CLOSE_TRUE = true;
        TcpipNetAddress tcpidRemoteAddress = null;
        if ((remoteAddress!=null) && (remoteAddress instanceof TcpipNetAddress)) {
            tcpidRemoteAddress = (TcpipNetAddress)remoteAddress;
        }
        NetSocket higherLayerSocket = TLSNetSocketUtil.
            createTLSSocket(lowerLayerSocket, tcpidRemoteAddress,
                    AUTO_CLOSE_TRUE, enabledCipherSuites, keyManagers, trustManagers);
        
           return higherLayerSocket;
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
