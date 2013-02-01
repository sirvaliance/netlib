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
package org.silvertunnel.netlib.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.logging.Logger;

import org.junit.Test;
import org.silvertunnel.netlib.api.util.IpNetAddress;

/**
 * Test HttpTestUtil.
 * 
 * @author hapke
 */
public class HttpTestUtilRemoteTest {
    private static final Logger log = Logger.getLogger(HttpTestUtilRemoteTest.class.getName());
    
    @Test
    public void testGetSourceIpNetAddress() throws Exception {
        NetLayer netLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP);
        
        // test 1
        IpNetAddress ip1 = HttpTestUtil.getSourceIpNetAddress(netLayer);
        log.info("ip1="+ip1);
        assertNotNull("wrong ip1", ip1);

        // test 2
        IpNetAddress ip2 = HttpTestUtil.getSourceIpNetAddress(netLayer);
        log.info("ip2="+ip2);
        assertNotNull("wrong ip2", ip2);
        
        // final check
        assertEquals("unexpected: ip1!=ip2", ip1, ip2);
    }
}
