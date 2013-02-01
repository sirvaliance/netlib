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

package org.silvertunnel.netlib.layer.tor.circuit;

import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import org.junit.Ignore;
import org.junit.Test;
import org.silvertunnel.netlib.adapter.url.NetlibURLStreamHandlerFactory;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;

/**
 * Test of the ability of TorNetLayer to handle connection setup
 * even if many TLSConnections and their circuits were interrupted.
 * 
 * Special test case(es) that use non-public methods of class Tor.
 * 
 * @author hapke
 */
public class TorLongTermRemoteTest {
    private static final Logger log = Logger.getLogger(TorLongTermRemoteTest.class.getName());

    /**
     * Test that multiple/long term use of NetlibURLStream and HandlerFactory work correctly.
     */
    @Test(timeout=900000)
    public void testLongTermUseOfNetlibURLStreamHandlerFactory() throws Exception {
        final int NUM_OF_DOWNLOADS = 10;
        
        List<String> responses = new ArrayList<String>(NUM_OF_DOWNLOADS);
        
        try {
            // classic:   TcpipNetLayer with NetLayerIDs.TCPIP (--> HTTP over plain TCP/IP)
            // anonymous: TorNetLayer with NetLayerIDs.TOR (--> HTTP over TCP/IP over Tor network)
            //NetLayer lowerNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP); 
            NetLayer lowerNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR); 
            lowerNetLayer.waitUntilReady();
            
            // prepare URL handling on top of the lowerNetLayer
            NetlibURLStreamHandlerFactory factory = new NetlibURLStreamHandlerFactory(false);
            // the following method could be called multiple times
            // to change layer used by the factory over the time:
            factory.setNetLayerForHttpHttpsFtp(lowerNetLayer);

            // create the suitable URL object
            URLStreamHandler handler = factory.createURLStreamHandler("http");
            
            // communicate via HTTP multiple times
            for (int i=1; i<=NUM_OF_DOWNLOADS; i++) {
                String id = "NetlibHttpUsageExamplesLongTimeRemoteTest"+i;
                String urlStr = "http://httptest.silvertunnel.org/httptest/bigtest.jsp?id="+id;
                URL context = null;
                URL url = new URL(context, urlStr, handler);
    
                // send request without POSTing data
                URLConnection urlConnection = url.openConnection();
                urlConnection.setDoInput(true); 
                urlConnection.setDoOutput(false); 
                urlConnection.connect();
    
                // receive and store the response as String
                BufferedReader response = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
                String line;
                StringBuffer responseStrBuf = new StringBuffer(); 
                while ((line=response.readLine())!=null) {
                    responseStrBuf.append(line);
                    responseStrBuf.append("\n");
                }
                response.close();
                String responseStr = responseStrBuf.toString();
                responses.add(responseStr);
                log.info("Response:\n"+responseStr+"\n");
                
                // check the response
                String responseIdStr = "<id>"+id+"</id>";
                assertTrue(
                        "response does not contains expected id string=\""+responseIdStr+"\":\n"+response,
                        responseStr.contains(responseIdStr));
                
                if (i>=2){
                    // close all TLS connections used by Tor
                    // to simulate connection aborts and connection timeouts 
                    TLSConnectionAdmin.closeAllTlsConnections();
                }
            }
        } catch (Exception e) {
            throw new Exception("Exception occured after reading "+responses.size()+" responses", e);
        } finally {
            // log all responses
            log.info("************************************");
            log.info("************************************");
            log.info("************************************");
            log.info("************************************");
            log.info("************************************");
            log.info("Number of responses: "+responses.size());
            for (String response : responses) {
                log.info("Response:\n"+response+"\n");
            }
        }
    }    
    
    @Ignore
    @Test(timeout=900000)
    public void testLongTermUseOfNetlibURLStreamHandlerFactory2() throws Exception {
        testLongTermUseOfNetlibURLStreamHandlerFactory();
    }

    @Ignore
    @Test(timeout=900000)
    public void testLongTermUseOfNetlibURLStreamHandlerFactory3() throws Exception {
        testLongTermUseOfNetlibURLStreamHandlerFactory();
    }
    
    @Ignore
    @Test(timeout=900000)
    public void testLongTermUseOfNetlibURLStreamHandlerFactory4() throws Exception {
        testLongTermUseOfNetlibURLStreamHandlerFactory();
    }
    
    @Ignore
    @Test(timeout=900000)
    public void testLongTermUseOfNetlibURLStreamHandlerFactory5() throws Exception {
        testLongTermUseOfNetlibURLStreamHandlerFactory();
    }
}
