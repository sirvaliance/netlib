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

package org.silvertunnel.netlib.layer.mock;

import static org.junit.Assert.assertEquals;

import java.util.logging.Logger;

import org.junit.Test;

/**
 * JUnit test to test closing the MockNetLayer.
 * 
 * @author hapke
 */
public class ClosingMockNetLayerLocalTest {
    private static final Logger log = Logger.getLogger(ClosingMockNetLayerLocalTest.class.getName());
    
    private volatile boolean threadClosedIS;
    
    @Test(timeout=5000)
    public void testClosingMockByteArrayInputStream() throws Exception {
        byte[] response = new byte[] {1};
        final long waitAtTheEndMs = 10000;
        final MockByteArrayInputStream is = new MockByteArrayInputStream(response, waitAtTheEndMs);
        
        // read first byte
        int b = is.read();
        assertEquals("wrong first byte", 1, b);
        
        // start thread to close the MockByteArrayInputStream after 1 second
        threadClosedIS = false;
        Thread t = new Thread() {
            @Override
            public void run() {
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    log.info("Thread interrupted");
                }
                threadClosedIS = true;
                is.close();
            }
        };
        t.start();
        
        // the thread must not be finished
        assertEquals("wrong state threadClosedIS, i.e. the Thread was too fast?", false, threadClosedIS);

        // read the second byte: this must block until close
        b = is.read();
        assertEquals("wrong second byte", -1, b);
        
        // the thread must already be finished
        assertEquals("wrong state threadClosedIS, i.e. the Thread did not yet close the MockByteArrayInputStream", true, threadClosedIS);
    }
}
