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
package org.silvertunnel.netlib.layer.socks;

import static org.silvertunnel.netlib.util.ByteArrayUtil.getByteArray;

import java.util.logging.Logger;

import org.junit.Before;
import org.junit.Test;
import org.silvertunnel.netlib.api.ByteArrayTestUtil;
import org.silvertunnel.netlib.api.HttpTestUtil;
import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.layer.tcpip.TcpipNetLayer;

/** see http://de.wikipedia.org/wiki/SOCKS#Das_SOCKS-5-Protokoll */
public class Socks5RemoteTest {
    private static final Logger log = Logger.getLogger(Socks5RemoteTest.class.getName());

    @Before
    public void setUp() throws Exception {
        // create layer
        NetLayer tcpipNetLayer = new TcpipNetLayer();
        NetLayer socksProxyNetLayer = new SocksServerNetLayer(tcpipNetLayer);
        NetFactory.getInstance().registerNetLayer(NetLayerIDs.SOCKS_OVER_TCPIP, socksProxyNetLayer);
    }


    @Test(timeout=3000)
    public void testSocks5EstablishClientConnection() throws Exception {
        // create connection
        NetSocket socksSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.SOCKS_OVER_TCPIP).
        		createNetSocket(null, (NetAddress)null, (NetAddress)null);
    
        // check socks negotiation
        byte[] request1 = getByteArray(
                0x05, 0x01, /*auth method:*/ 0x00);
        byte[] expectedResponse1 = getByteArray(
                0x05, /*auth method:*/ 0x00);
        socksSocket.getOutputStream().write(request1);
        socksSocket.getOutputStream().flush();
        ByteArrayTestUtil.assertByteArrayFromInputStream(log, "wrong response1", expectedResponse1, socksSocket.getInputStream()); 
        
        // check connection setup
        byte[] request2 = getByteArray(
                0x05, /*TCP client:*/ 0x01, 0x00, /*with domain name:*/ 0x03, 
                /*domain name len:*/ 0x10, 's', 'i', 'l', 'v', 'e', 'r', 't', 'u', 'n', 'n', 'e', 'l', '.', 'o', 'r', 'g',
                /*2 bytes port*/ 0x00, 80);
        byte[] expectedResponse2 = getByteArray(
                0x05, /*reply code:*/ 0x00, 0x00, /*with domain name:*/ 0x03, 
                /*domain name len:*/ 0x10, 's', 'i', 'l', 'v', 'e', 'r', 't', 'u', 'n', 'n', 'e', 'l', '.', 'o', 'r', 'g',
                /*2 bytes port*/ 0x00, 80);
        socksSocket.getOutputStream().write(request2);
        socksSocket.getOutputStream().flush();
        ByteArrayTestUtil.assertByteArrayFromInputStream(log, "wrong response2", expectedResponse2, socksSocket.getInputStream()); 
        
        // check open connection
        HttpTestUtil.executeSmallTest(socksSocket, "testSocks5EstablishClientConnection", 2000);
    }
}
