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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.util.logging.Logger;

import org.junit.Ignore;
import org.junit.Test;
import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.mock.MockNetLayer;

public class ControlNetLayerLocalTest {
    private static Logger log = Logger.getLogger(ControlNetLayerLocalTest.class.getName());

    private static final long TIMEOUT_100MILLIS = 100L;
    private static final long TIMEOUT_1000MILLIS = 1000L;
    private static final long TIMEOUT_1500MILLIS = 1500L;
    private static final long TIMEOUT_2000MILLIS = 2000L;
    private static final long TIMEOUT_3000MILLIS = 3000L;
    private static final long TIMEOUT_5000MILLIS = 5000L;
    private static final long TIMEOUT_10SECONDS = 10000L;
    private static final byte BYTE1 = 77;
    private static final byte[] ONE_BYTE = new byte[] {BYTE1};
    private static final byte[] SIX_BYTES = new byte[] {BYTE1, BYTE1, BYTE1, BYTE1, BYTE1, BYTE1};
    private static final byte END_OF_STREAM = -1;
    
    
    @Test(timeout=3000)
    public void testConnectionWithoutTimeoutRisen() throws Exception {
        // set control/timeout parameters
        ControlParameters cp = ControlParameters.createUnlimitedParameters();
        
        // initialize NetLayer
        MockNetLayer lowerNetLayer = new MockNetLayer(ONE_BYTE, false, TIMEOUT_1000MILLIS);
        ControlNetLayer netLayer = new ControlNetLayer(lowerNetLayer, cp);
        
        // create connection
        NetSocket s = netLayer.createNetSocket(null, null, null);
        InputStream is = s.getInputStream();
        
        // read data
        log.info("start reading now");
        assertEquals("wrong 1st byte", BYTE1, is.read());
        assertEquals("wrong 1nd byte", END_OF_STREAM, is.read());
        log.info("stop reading now");
        
        // close
        is.close();
        s.close();
   }

    @Test(timeout=3000)
    public void testConnectionWithOverallTimeoutRisen() throws Exception {
        // set control/timeout parameters
        ControlParameters cp = ControlParameters.createUnlimitedParameters();
        cp.setOverallTimeoutMillis(TIMEOUT_1000MILLIS);
        
        // initialize NetLayer
        MockNetLayer lowerNetLayer = new MockNetLayer(ONE_BYTE, false, TIMEOUT_10SECONDS);
        ControlNetLayer netLayer = new ControlNetLayer(lowerNetLayer, cp);
        
        // create connection
        NetSocket s = netLayer.createNetSocket(null, null, null);
        InputStream is = s.getInputStream();
        
        // read data
        log.info("start reading now");
        assertEquals("wrong 1st byte", BYTE1, is.read());
        
        // expect exception because of timeout
        try {
            is.read();
            fail("expected InterruptedIOException not thrown");
        } catch (InterruptedIOException e) {
            // this is expected
        }
        log.info("stop reading now");
        
        // close
        is.close();
        s.close();
    }
    
    @Test(timeout=15000)
    public void testConnectionWithouThroughputTimeframeTimeoutRisen() throws Exception {
        // set control/timeout parameters: min. throughput 1.33 byte/second
        ControlParameters cp = ControlParameters.createUnlimitedParameters();
        cp.setThroughputTimeframeMinBytes(2);
        cp.setThroughputTimeframeMillis(TIMEOUT_1500MILLIS);
        
        // initialize NetLayer
        final long NOWAIT = 0;
        MockNetLayer lowerNetLayer = new MockNetLayer(SIX_BYTES, false, NOWAIT);
        ControlNetLayer netLayer = new ControlNetLayer(lowerNetLayer, cp);
        
        // create connection
        NetSocket s = netLayer.createNetSocket(null, null, null);
        InputStream is = s.getInputStream();
        
        // read data with 2 bytes/second
        log.info("start reading now");
        assertEquals("wrong 1st byte", BYTE1, is.read());
        assertEquals("wrong 2nd byte", BYTE1, is.read());
        Thread.sleep(TIMEOUT_1000MILLIS);
        assertEquals("wrong 3rd byte", BYTE1, is.read());
        assertEquals("wrong 4th byte", BYTE1, is.read());
        Thread.sleep(TIMEOUT_1000MILLIS);
        assertEquals("wrong 5th byte", BYTE1, is.read());
        assertEquals("wrong 6th byte", BYTE1, is.read());
        Thread.sleep(TIMEOUT_1000MILLIS);
        assertEquals("wrong 7th byte", END_OF_STREAM, is.read());
        log.info("stop reading now");
        
        // close
        is.close();
        s.close();
        
        // wait a bit - to see (in the logfile only!) whether timeout checking was finished after closing the socket
        log.info("final sleep ...");
        Thread.sleep(TIMEOUT_5000MILLIS);
    }
    
    @Test(timeout=10000)
    public void testConnectionWithThroughputTimeframeTimeoutRisen() throws Exception {
        // set control/timeout parameters: min. throughput 4 bytes/second
        ControlParameters cp = ControlParameters.createUnlimitedParameters();
        cp.setThroughputTimeframeMinBytes(6);
        cp.setThroughputTimeframeMillis(TIMEOUT_1500MILLIS);
        
        // initialize NetLayer
        final long NOWAIT = 0;
        MockNetLayer lowerNetLayer = new MockNetLayer(SIX_BYTES, false, NOWAIT);
        ControlNetLayer netLayer = new ControlNetLayer(lowerNetLayer, cp);
        
        // create connection
        NetSocket s = netLayer.createNetSocket(null, null, null);
        InputStream is = s.getInputStream();
        
        // read data with 2 bytes/second
        log.info("start reading now");
        assertEquals("wrong 1st byte", BYTE1, is.read());
        assertEquals("wrong 2nd byte", BYTE1, is.read());
        Thread.sleep(TIMEOUT_1000MILLIS);
        assertEquals("wrong 3rd byte", BYTE1, is.read());
        assertEquals("wrong 4th byte", BYTE1, is.read());
        Thread.sleep(TIMEOUT_1000MILLIS);
        
        // now an exception should be thrown because of "throughput is too low"
        try {
            is.read();
            fail("expected InterruptedIOException not thrown");
        } catch (InterruptedIOException e) {
            // this is expected
        }
        log.info("stop reading now");
        
        // close
        is.close();
        s.close();
    }


    /**
     * This test case is only intended to (manually) verify the error logging in the case of a time out.
     *  
     * @throws Exception
     */
    @Ignore
    @Test(timeout=5000)
    public void testConnectionWithThroughputTimeframeTimeoutRisen_TcpipNetLayer_show_error_message() throws Exception {
        NetLayer netLayer =  NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP);
        enforceTimeoutAndCatchException(netLayer, new TcpipNetAddress("silvertunnel.org", 80));
    }
        
    /**
     * This test case is only intended to (manually) verify the error logging in the case of a time out.
     *  
     * @throws Exception
     */
    @Ignore
    @Test(timeout=15000)
    public void testConnectionWithThroughputTimeframeTimeoutRisen_TlsNetLayer_show_error_message() throws Exception {
        NetLayer netLayer =  NetFactory.getInstance().getNetLayerById(NetLayerIDs.TLS_OVER_TCPIP);
        enforceTimeoutAndCatchException(netLayer, new TcpipNetAddress("silvertunnel.org", 443));
    }

    /**
     * This test case is only intended to (manually) verify the error logging in the case of a time out.
     *  
     * @throws Exception
     */
    @Ignore
    @Test(timeout=120000)
    public void testConnectionWithThroughputTimeframeTimeoutRisen_TorNetLayer_show_error_message() throws Exception {
        NetLayer netLayer =  NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR);
        enforceTimeoutAndCatchException(netLayer, new TcpipNetAddress("silvertunnel.org", 80));
    }

    private void enforceTimeoutAndCatchException(NetLayer netLayer, NetAddress remoteNetAddress){
        try {
            // set control/timeout parameters: unreachable throughput
            ControlParameters cp = ControlParameters.createUnlimitedParameters();
            cp.setThroughputTimeframeMinBytes(Long.MAX_VALUE);
            cp.setThroughputTimeframeMillis(1);
            
            // initialize NetLayer
            ControlNetLayer controlNetLayer = new ControlNetLayer(netLayer, cp);
            
            // create connection
            NetSocket s = controlNetLayer.createNetSocket(null, null, remoteNetAddress);
            InputStream is = s.getInputStream();
            
            // read data; expect timeout
            log.info("start reading now");
            try {
                is.read();
                is.read();
                is.read();
                is.read();
                is.read();
            } finally {
                // close
                is.close();
                s.close();
            }
        } catch (IOException e) {
            // expected
        }
    }
    
}
