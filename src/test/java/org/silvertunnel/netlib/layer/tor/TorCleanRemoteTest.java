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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.logging.Logger;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.silvertunnel.netlib.api.HttpTestUtil;
import org.silvertunnel.netlib.api.util.IpNetAddress;

import ch.unibe.jexample.Given;
import ch.unibe.jexample.JExample;

/**
 * Test the support of .exit host names to specify Tor exit nodes.
 * 
 * @author hapke
 */
@RunWith(JExample.class)
public class TorCleanRemoteTest extends TorRemoteAbstractTest {
    private static final Logger log = Logger.getLogger(TorCleanRemoteTest.class.getName());

    @Test(timeout=600000)
    public void initializeTor() throws Exception {
        // repeat method declaration here to be the first test method of the class
        super.initializeTor();
    }
        
    @Test(timeout=15000)
    @Given("#initializeTor")
    public void testTwoConnectionsWithoutReset() throws Exception {
        // determine 1st exit node id
        IpNetAddress exitNodeIp1 = HttpTestUtil.getSourceIpNetAddress(torNetLayer);
        log.info("exitNodeIp1="+exitNodeIp1);

        // determine 2nd exit node id
        IpNetAddress exitNodeIp2 = HttpTestUtil.getSourceIpNetAddress(torNetLayer);
        log.info("exitNodeIp2="+exitNodeIp2);
        log.info("exitNodeIp1="+exitNodeIp1);
        
        assertEquals("exitNodeIp1!=exitNodeIp2 (but not expected)", exitNodeIp1, exitNodeIp2);
    }
    
    @Test(timeout=15000)
    @Given("#initializeTor")
    public void testTwoConnectionsWithReset() throws Exception {
        // determine 1st exit node id
        IpNetAddress exitNodeIp1 = HttpTestUtil.getSourceIpNetAddress(torNetLayer);
        log.info("exitNodeIp1="+exitNodeIp1);
        assertNotNull("exitNodeIp1==null", exitNodeIp1);

        // reset ToNetLayer state
        torNetLayer.clear();
        
        // determine 2nd exit node id
        IpNetAddress exitNodeIp2 = HttpTestUtil.getSourceIpNetAddress(torNetLayer);
        log.info("exitNodeIp2="+exitNodeIp2);
        assertNotNull("exitNodeIp1==null", exitNodeIp1);

        // log again to simplify log file reading
        log.info("exitNodeIp1="+exitNodeIp1);
        
        // check
        if (exitNodeIp1.equals(exitNodeIp2)) {
            fail("exitNodeIp1==exitNodeIp2 (but not expected)");
        }
   }
    /*
    @Test(timeout=15000)
    @Given("#initializeTor")
    public void testWithHostname2() throws Exception {
        testWithHostname();
    }
    */
}
