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
package org.silvertunnel.netlib.layer.redirect;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Before;
import org.junit.Test;
import org.silvertunnel.netlib.api.ByteArrayTestUtil;
import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.TestUtil;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.mock.MockNetLayer;
import org.silvertunnel.netlib.util.ByteArrayUtil;

/**
 * Test ForwardingNetLayer.
 * 
 * In detail: test a forward over a forward over a mock.
 * 
 * @author hapke
 */
public class ForwardingLocalTest {
    private static final Logger log = Logger.getLogger(ForwardingLocalTest.class.getName());

    private byte[] USER_DATA_REQUEST;
    private byte[] USER_DATA_RESPONSE;
    
    private MockNetLayer mockNetLayer;
    private NetLayer forward1OverMockNetLayer;
    private NetAddress forward1NetAddress;
    private NetLayer forward2OverForward1OverMockNetLayer;
    private NetAddress forward2NetAddress;
    
    public ForwardingLocalTest() {
        try {
            USER_DATA_REQUEST = ByteArrayUtil.getByteArray("Das ist mein Request", 5000, "\u00e0.");
            USER_DATA_RESPONSE = ByteArrayUtil.getByteArray("Hier ist\n\nmeine Antwort\n fuer heute", 3000, "\u00e0.");
            
        } catch (Exception e) {
            log.log(Level.SEVERE, "unexpected during construction", e);
        }
    }

    @Before
    public void setUp() throws Exception {
        // create layers
        final long WAIT_ENDLESS = -1;
        mockNetLayer = new MockNetLayer(USER_DATA_RESPONSE, false, WAIT_ENDLESS);
        forward1NetAddress = new TcpipNetAddress("do.mein.eins", 81);
        forward1OverMockNetLayer = new ForwardingNetLayer(mockNetLayer, null, null, forward1NetAddress);
        forward2NetAddress = new TcpipNetAddress("do.mein.zwei", 82);
        forward2OverForward1OverMockNetLayer = new ForwardingNetLayer(forward1OverMockNetLayer, null, null, forward2NetAddress);
    }
    
    @Test(timeout=1000)
    public void testSocks5EstablishClientConnection() throws Exception {
        // create connection
        NetAddress remoteAddress = new TcpipNetAddress("do.meins", 80);
        final NetSocket socksSocket = forward2OverForward1OverMockNetLayer.createNetSocket(null, null, remoteAddress);
    
        
        // send user data to remote side
        socksSocket.getOutputStream().write(USER_DATA_REQUEST);
        socksSocket.getOutputStream().flush();

        // receive and check user data from remote side
        ByteArrayTestUtil.assertByteArrayFromInputStream(null, "wrong user data response", USER_DATA_RESPONSE, socksSocket.getInputStream()); 
        
        // check user data received by the remote side (mock)
        TestUtil.waitUntilMinimumNumberOfReceivedBytes(mockNetLayer.getFirstSessionHistory(), USER_DATA_REQUEST.length);
        socksSocket.close();
        NetAddress expectedNetAddress = forward1NetAddress;
        TestUtil.assertMockNetLayerSavedData("wrong data received by mock", mockNetLayer.getFirstSessionHistory(), USER_DATA_REQUEST, expectedNetAddress);
    }
}
