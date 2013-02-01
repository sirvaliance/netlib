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

import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.logging.Logger;

import org.junit.Ignore;
import org.junit.Test;
import org.silvertunnel.netlib.adapter.url.NetlibURLStreamHandlerFactory;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;


/**
 * Test that reading system properties in TorConfic static constructor works.
 * 
 * These tests are not executed by default.
 * 
 * @author hapke
 */
public class DynamicTorconfigRemoteTest {
    private static final Logger log = Logger.getLogger(DynamicTorconfigRemoteTest.class.getName());

    @Ignore
    @Test(timeout=120000)
    public void test_HTTP_GET_with_Adapter_URL() throws Exception {
        //
        // setting system properties
        //
        
        // reasonable values: 2, 3, 5
        // default: 5
        System.setProperty("torMinimumIdleCircuits", "2");

        // reasonable values: 30000, 20000, 10000
        // default: 10000
        System.setProperty("torMaxAllowedSetupDurationMs", "30000");

        
        //
        // execute the test
        log.info("Before generating lowerNetLayer");
        NetLayer lowerNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR);
        log.info("Generated a lowerNetLayer");

        log.info("Before TOR is started up");
        ((TorNetLayer)lowerNetLayer).waitUntilReady();
        log.info("Successfully started TOR");
        
        log.info("Before running NetlibURLStreamHandlerFactory");
        NetlibURLStreamHandlerFactory factory = new NetlibURLStreamHandlerFactory(false);
        factory.setNetLayerForHttpHttpsFtp(lowerNetLayer);
        log.info("After running NetlibURLStreamHandlerFactory");

        log.info("Before assigning URL protocol");
        String urlStr = "http://check.torproject.org";
        URLStreamHandler handler = factory.createURLStreamHandler("http");
        URL context = null;
        URL url = new URL(context, urlStr, handler);
        log.info("After assigning URL protocol");

        log.info("Before openning URL connection");
        URLConnection urlConnection = url.openConnection();
        urlConnection.setDoInput(true);
        urlConnection.setDoOutput(false);
        urlConnection.connect();
        log.info("After openning URL connection");
    }
}
