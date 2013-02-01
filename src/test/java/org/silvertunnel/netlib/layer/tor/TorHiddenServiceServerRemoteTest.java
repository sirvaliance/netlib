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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.util.ByteArrayUtil;
import org.silvertunnel.netlib.util.FileUtil;
import org.silvertunnel.netlib.util.HttpUtil;

import ch.unibe.jexample.Given;
import ch.unibe.jexample.JExample;



/**
 * Test Tor's hidden services (server-sideTorHiddenServicePrivateNetAddress netAddressWithoutPort = /service implementation).
 * 
 * @author hapke
 */
//@RunWith(JExample.class)
public class TorHiddenServiceServerRemoteTest extends TorRemoteAbstractTest {
    private static final Logger log = Logger.getLogger(TorHiddenServiceServerRemoteTest.class.getName());
 
    private static final DateFormat DF = new SimpleDateFormat("yyyyMMddHHmmssSSS"); 
    protected static TorNetLayerUtil torNetLayerUtil = TorNetLayerUtil.getInstance();
    protected static FileUtil fileUtil = FileUtil.getInstance();
    
    protected static TcpipNetAddress publicNewHiddenServiceTcpipNetAddress; 
    protected static TcpipNetAddress publicOldHiddenServiceTcpipNetAddress; 
 
    public static final String OLD_HIDDEN_SERVICE_PRIVATE_KEY_PEM_PATH = TorNetLayerUtilLocalTest.EXAMPLE_PRIVATE_KEY_PEM_PATH;
    
    @Test
    public void trivialTest() throws Exception {
        // always successful
    }
       
    ///////////////////////////////////////////////////////
    // startup
    ///////////////////////////////////////////////////////

    /**
     * Start TorNetLayer.
     */
    @Test(timeout=600000)
    @Given("#trivialTest")
    public void initializeTor() throws Exception {
        // repeat method declaration here to be the first test method of the class
        super.initializeTor();
    }
 

    ///////////////////////////////////////////////////////
    // provide hidden service(s)
    ///////////////////////////////////////////////////////
    
    /**
     * 
     * @param responseStr             will be part of each HTTP response of the server
     * @param netAddressWithoutPort   hidden service private address
     * @return hidden service public address
     * @throws Exception
     */
    private TcpipNetAddress provideHiddenService(final String responseStr, TorHiddenServicePrivateNetAddress netAddressWithoutPort) throws Exception {
        // create net address inclusive port number
        final int PORT80 = 80;
        TorHiddenServicePortPrivateNetAddress netAddress =
            new TorHiddenServicePortPrivateNetAddress(netAddressWithoutPort, PORT80);
        log.info("netAddress="+netAddress);
        
        // establish the hidden service
        final TorNetServerSocket netServerSocket = (TorNetServerSocket)torNetLayer.createNetServerSocket(null, netAddress);
        
        // start a thread that waits for incoming connections 
        new Thread() {
            @Override
            public void run() {
                try {
                    while (true) {
                        // accept one new incoming connection per loop cycle
                        log.info("TOR TEST: wait for accept");
                        final NetSocket netSocket = netServerSocket.accept();
                        log.info("TOR TEST: accept returned");
                        
                        // handle the new connection in an extra thread
                        new Thread() {
                            @Override
                            public void run() {
                                try {
                                    processOneServerSideConnection(netSocket, responseStr);
                                } catch (Exception e) {
                                    log.log(Level.WARNING, "exception while handling a server side connection", e);
                                }
                            }
                        }.start();
                    }
                } catch (Exception e) {
                    log.log(Level.WARNING, "exception while handling server side connections", e);
                }
            }
        }.start();
        
        // save public address of this service for later access of the client
        TcpipNetAddress publicHiddenServiceTcpipNetAddress = netAddress.getPublicTcpipNetAddress();
        log.info("publicHiddenServiceTcpipNetAddress="+publicHiddenServiceTcpipNetAddress);
        return publicHiddenServiceTcpipNetAddress;
    }
    /**
     * Handle one server-side connection of the hidden service.
     * Read the request and write a HTTP response.
     * 
     * @param netSocket    freshly opened connection to a (HTTP?) client
     * @throws Exception
     */
    private void processOneServerSideConnection(NetSocket netSocket, String responseStr) throws Exception {
        // read the first request line
        BufferedReader reader = new BufferedReader(new InputStreamReader(netSocket.getInputStream()));
        log.info("TOR HIDDEN SERVICE - SERVER SIDE: wait for first line");
        String firstLine = reader.readLine();
        log.info("TOR HIDDEN SERVICE - SERVER SIDE: firstLine="+firstLine);

        // send response
        String response =
            "HTTP/1.1 200 OK\n\r"+
            "Content-Type: text/xml; charset=utf-8\n\r"+
            "\n\r"+
            "<html><body>This is my response\nwith two lines\n"+responseStr+"\ndate/time="+getCurrentTime()+"</body></html>";
        Writer writer = new OutputStreamWriter(netSocket.getOutputStream());
        writer.append(response);
        writer.flush();
        log.info("TOR HIDDEN SERVICE - SERVER SIDE: send response="+response);
        
        Thread.sleep(5000);
        
        writer.close();
        reader.close();
        netSocket.close();
    }

    
    
    /**
     * Provide the NEW hidden service and
     * establish a Thread that wait for incoming connections.
     * 
     * @throws Exception
     */
    @Test(timeout=240000)
    @Given("#initializeTor")
    public void test_phase1_provideNewHiddenService() throws Exception {
        super.initializeTor();
        TorHiddenServicePrivateNetAddress netAddressWithoutPort = torNetLayerUtil.createNewTorHiddenServicePrivateNetAddress();

        // in real live this netAddressWithoutPort should be saved on persistent media
        // for latter reuse, e.g.:
        // torNetLayerUtil.writeTorHiddenServicePrivateNetAddressToFiles(directory, netAddressWithoutPort);

        publicNewHiddenServiceTcpipNetAddress = provideHiddenService("NEW-SERVICE", netAddressWithoutPort);
    }

    /**
     * Provide the OLD hidden service (based on existing private key) and
     * establish a Thread that wait for incoming connections.
     * 
     * @throws Exception
     */
    @Test(timeout=240000)
    @Given("#initializeTor")
    public void test_phase2_provideOldHiddenService() throws Exception {
        super.initializeTor();
        // read private key of OLD hidden service
        String privateKeyPEMStr = fileUtil.readFileFromClasspath(OLD_HIDDEN_SERVICE_PRIVATE_KEY_PEM_PATH);
        TorHiddenServicePrivateNetAddress netAddressWithoutPort = 
            torNetLayerUtil.parseTorHiddenServicePrivateNetAddressFromStrings(privateKeyPEMStr, null, false);

        // start OLD hidden service
        publicOldHiddenServiceTcpipNetAddress = provideHiddenService("old-service", netAddressWithoutPort);
    }
    
    
    ///////////////////////////////////////////////////////
    // test access to the hidden service(s) with silvertunnel.org Netlib 
    ///////////////////////////////////////////////////////
    
    private void checkAccessProvidedHiddenService(TcpipNetAddress publicHiddenServiceTcpipNetAddress, String expectedResponseStr) throws Exception {
        // pre-check
        assertNotNull("publicHiddenServiceTcpipNetAddress==null", publicNewHiddenServiceTcpipNetAddress);

        // create connection
        NetSocket topSocket = null;
        try {
            topSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR_OVER_TLS_OVER_TCPIP).
                createNetSocket(null, null, publicHiddenServiceTcpipNetAddress);
    
            // communicate with the remote side
            byte[] httpResponse = HttpUtil.getInstance().get(
                    topSocket, publicHiddenServiceTcpipNetAddress, "/get/info/from/hidden/service/"+getCurrentTime(), 60000);
            String httpResponseStr = ByteArrayUtil.showAsString(httpResponse);
            log.info("http response body: "+ httpResponseStr);
            
            // make the httpResponseStr readable in HTML reports
            httpResponseStr = removeHtmlTags(httpResponseStr);
    
            // check result
            final String SUCCESS_STR1 = "This is my response";
            if (!httpResponseStr.contains(SUCCESS_STR1)) {
                fail("did not get correct response of hidden service (1), response body="+httpResponseStr);
            }
            final String SUCCESS_STR2 = expectedResponseStr;
            if (!httpResponseStr.contains(SUCCESS_STR2)) {
                fail("did not get correct response of hidden service (2), response body="+httpResponseStr);
            }
        } finally {
            if (topSocket!=null) {
                topSocket.close();
            }
        }
    }

    //@Ignore
    @Test(timeout=120000)
    @Given("#test_phase1_provideNewHiddenService")
    public void test_phase3_accessProvidedNewHiddenService() throws Exception {
        test_phase1_provideNewHiddenService();
        checkAccessProvidedHiddenService(publicNewHiddenServiceTcpipNetAddress, "NEW-SERVICE");
    }
    
    //@Ignore
    @Test(timeout=120000)
    @Given("#test_phase1_provideNewHiddenService")
    public void test_phase3a_accessProvidedNewHiddenService_again() throws Exception {
        log.info("start to do it again");
        test_phase3_accessProvidedNewHiddenService();
    }

    @Test(timeout=120000)
    @Given("#test_phase2_provideOldHiddenService")
    public void test_phase4_accessProvidedOldHiddenService() throws Exception {
        test_phase2_provideOldHiddenService();
        checkAccessProvidedHiddenService(publicOldHiddenServiceTcpipNetAddress, "old-service");
    }

    @Test(timeout=120000)
    @Given("#test_phase2_provideOldHiddenService")
    public void test_phase4a_accessProvidedOldHiddenService_again() throws Exception {
        log.info("start to do it again");
        test_phase4_accessProvidedOldHiddenService();
    }
   

    ///////////////////////////////////////////////////////
    // test access to the hidden service(s) with proxy (only for NEW hidden service) 
    ///////////////////////////////////////////////////////

    /**
     * Test with tor2web proxy.
     * Hint: this only works for hidden services listen on port 80.
     * 
     * @throws Exception
     */
    //@Ignore
    @Test(timeout=180000)
    @Given("#test_phase1_provideNewHiddenService")
    public void test_phase5_accessProvidedNewHiddenService_via_originalTor_with_tor2web_org()  throws Exception {
        test_phase1_provideNewHiddenService();
        log.info("use tor2web proxy now");
        // sleep be be able to manually connect to the tor2web proxy
        //Thread.sleep(240000);

        // create a URL of tor2web proxy, like "https://4xuwatxuqzfnqjuz.tor2web.org/"
        String path = "/bla/blub/"+getCurrentTime();
        final int PORT443 = 443;
        TcpipNetAddress proxyTcpipNetAddress = new TcpipNetAddress(
                publicNewHiddenServiceTcpipNetAddress.getHostnameOrIpaddress().replace("onion", "tor2web.org"), PORT443);
        String url = "https://"+proxyTcpipNetAddress.getHostname()+path;
        log.info("url="+url);
        log.info("proxyTcpipNetAddress="+proxyTcpipNetAddress);

        // create connection to tor2web proxy
        NetSocket topSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TLS_OVER_TCPIP).createNetSocket(null, null, proxyTcpipNetAddress);

        // communicate with the remote side
        byte[] httpResponse = HttpUtil.getInstance().get(topSocket, proxyTcpipNetAddress, path, 150000);
        String httpResponseStr = ByteArrayUtil.showAsString(httpResponse);
        log.info("http response body: "+ httpResponseStr);
        
        // make the httpResponseStr readable in HTML reports
        httpResponseStr = removeHtmlTags(httpResponseStr);

        // check result
        final String SUCCESS_STR = "This is my response";
        if (!httpResponseStr.contains(SUCCESS_STR)) {
            fail("did not get correct response of hidden service, response body="+httpResponseStr);
        }
    }

    //@Ignore
    @Test(timeout=180000)
    @Given("#test_phase1_provideNewHiddenService")
    public void test_phase5a_accessProvidedNewHiddenService_via_originalTor_with_tor2web_org_again()  throws Exception {
        log.info("start to do it again");
        test_phase5_accessProvidedNewHiddenService_via_originalTor_with_tor2web_org();
    }

    
    
    
    
    
    
    ///////////////////////////////////////////////////////
    // internal helper methods (without business logic)
    ///////////////////////////////////////////////////////

    private String getCurrentTime() {
        return DF.format(new Date());
    }
}
