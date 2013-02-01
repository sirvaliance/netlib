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

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import org.junit.Before;
import org.junit.Test;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerStatus;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.IpNetAddress;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.mock.MockNetLayer;

/**
 * Test ConditionalNetLayer.
 * 
 * @author hapke
 */
public class ConditionalNetLayerLocalTest {
    private static final Logger log = Logger.getLogger(ConditionalNetLayerLocalTest.class.getName());

    private NetLayer lowerNetLayer1;
    private NetLayer lowerNetLayer2;
    private NetLayer lowerNetLayer3;
    
    private NetLayer conditionalNetLayer;
    
    @Before
    public void setUp() throws Exception {
        // initialize lower layers
        final long DO_NOT_WAIT = 0;
        lowerNetLayer1 = new MockNetLayer(new byte[] {1}, true, DO_NOT_WAIT);
        lowerNetLayer2 = new MockNetLayer(new byte[] {2}, true, DO_NOT_WAIT);
        lowerNetLayer3 = new MockNetLayer(new byte[] {3}, true, DO_NOT_WAIT);
        
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(new Condition(new IpNetAddress("127.0.0.1"), lowerNetLayer1));
        conditions.add(new Condition(new IpNetAddress("127.0.0.11"), lowerNetLayer2));
        conditions.add(new Condition("www.localhost.com", lowerNetLayer2));
        conditions.add(new Condition("localhost", lowerNetLayer1));
        conditions.add(new Condition(new TcpipNetAddress("1.2.3.4:80"), lowerNetLayer1));
        conditions.add(new Condition(new TcpipNetAddress("1.2.3.4:800"), lowerNetLayer2));
        conditions.add(new Condition(Pattern.compile("99\\.88\\..+\\..+:\\d+"), lowerNetLayer1));
        conditions.add(new Condition(Pattern.compile("myspecialdomain\\.com:\\d+"), lowerNetLayer1));
        conditions.add(new Condition(Pattern.compile(".*\\.myspecialdomain\\.com:\\d+"), lowerNetLayer2));
        conditionalNetLayer = new ConditionalNetLayer(conditions, lowerNetLayer3);
    }
    
    /**
     * Test ConditionalNetLayer.createNetSocket().
     * 
     * @throws Exception
     */
    @Test(timeout=1000)
    public void testCreateSocket() throws Exception {
        assertEquals("wrong result (test 127.0.0.1:80)",
                1, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("127.0.0.1:80"))));
    	assertEquals("wrong result (test 127.0.0.1:22)",
    	        1, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("127.0.0.1:22"))));
        assertEquals("wrong result (test 127.0.0.11:22)",
                2, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("127.0.0.11:22"))));
        assertEquals("wrong result (test 127.0.0.111:22)",
                3, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("127.0.0.111:22"))));
        assertEquals("wrong result (test my.www.localhost.com:8080)",
                3, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("my.www.localhost.com:8080"))));
        assertEquals("wrong result (test www.localhost.com:8080)",
                2, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("www.localhost.com:8080"))));
        assertEquals("wrong result (test localhost:8080)",
                1, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("localhost:8080"))));
        assertEquals("wrong result (test localhost.loc:8080)",
                3, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("localhost.loc:8080"))));
        assertEquals("wrong result (test 1.2.3.4:80)",
                1, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("1.2.3.4:80"))));
        assertEquals("wrong result (test 1.2.3.4:800)",
                2, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("1.2.3.4:800"))));
        assertEquals("wrong result (test 1.2.3.4:8000)",
                3, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("1.2.3.4:8000"))));
        assertEquals("wrong result (test 1.2.3.44:80)",
                3, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("1.2.3.44:80"))));
        assertEquals("wrong result (test 11.22.33.44:80)",
                3, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("11.22.33.44:80"))));
        assertEquals("wrong result (test some.domain.com:80)",
                3, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("some.domain.com:80"))));
        assertEquals("wrong result (test 99.88.0.1:80)",
                1, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("99.88.0.1:80"))));
        assertEquals("wrong result (test 99.88.1.0:80)",
                1, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("99.88.1.0:80"))));
        assertEquals("wrong result (test myspecialdomain.com:80)",
                1, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("myspecialdomain.com:80"))));
        assertEquals("wrong result (test foo.myspecialdomain.com:80)",
                2, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("foo.myspecialdomain.com:80"))));
        assertEquals("wrong result (test notmyspecialdomain.com:80)",
                3, getNetLayerId(conditionalNetLayer.createNetSocket(null, null, new TcpipNetAddress("notmyspecialdomain.com.com:80"))));
    }
    
    @Test(timeout=1000)
    public void testGetStatus() {
    	assertEquals("wrong result of getStatus", NetLayerStatus.READY, conditionalNetLayer.getStatus());
    }
    
    @Test(timeout=1000)
    public void testWaitUntilReady() {
    	// should not block
    	conditionalNetLayer.waitUntilReady();
    }
    
    @Test(timeout=1000)
    public void testClear() throws Exception {
    	// should not block
    	conditionalNetLayer.clear();
    }
    
    @Test(timeout=1000)
    public void testGetNetAddressNameServiceSimple() throws Exception {
    	// should not block
    	conditionalNetLayer.getNetAddressNameService();
    }

    
    /**
     * Usage example inclusive full initialization.
     * 
     * @throws Exception
     */
    @Test(timeout=1000)
    public void testFullExample() throws Exception {
        // define when to use lowerNetLayer1 and when not to use it
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(new Condition(new IpNetAddress("127.0.0.1"), lowerNetLayer1));
        conditions.add(new Condition("localhost", lowerNetLayer1));
        NetLayer netLayer = new ConditionalNetLayer(conditions, lowerNetLayer2);

        // check behavior
        assertEquals("wrong result (test 127.0.0.1:80)",
                1, getNetLayerId(netLayer.createNetSocket(null, null, new TcpipNetAddress("127.0.0.1:80"))));
        assertEquals("wrong result (test 127.0.0.2:80)",
                2, getNetLayerId(netLayer.createNetSocket(null, null, new TcpipNetAddress("127.0.0.2:80"))));
        assertEquals("wrong result (test localhost:80)",
                1, getNetLayerId(netLayer.createNetSocket(null, null, new TcpipNetAddress("localhost:80"))));
        assertEquals("wrong result (test otherhost:80)",
                2, getNetLayerId(netLayer.createNetSocket(null, null, new TcpipNetAddress("otherhost:80"))));
    }
    
    
    ///////////////////////////////////////////////////////
    // internal helper method(s)
    ///////////////////////////////////////////////////////
    
    /**
     * Read the first byte form the stream - this will be used to identify the Mock instance.
     *  
     * @param netSocket
     * @return
     * @throws IOException
     */
    private int getNetLayerId(NetSocket netSocket) throws IOException {
        int firstByte = netSocket.getInputStream().read();
        return firstByte;
    }
}
