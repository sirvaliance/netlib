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
import static org.junit.Assert.fail;
import static org.silvertunnel.netlib.util.HttpUtil.HTTPTEST_SERVER_NETADDRESS;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.silvertunnel.netlib.api.util.IpNetAddress;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.util.ByteArrayUtil;
import org.silvertunnel.netlib.util.HttpUtil;

/**
 * Support Tests with HTTP.
 * 
 * @author hapke
 */
public class HttpTestUtil {
    private static final Logger log = Logger.getLogger(HttpTestUtil.class.getName());

    private static final String BEGIN = "Begin";
    private static final String END = "enD";
    public static final byte[] HTTPTEST_TESTFILE_CONTENT_testfile100000bytes =
        ByteArrayUtil.getByteArray(BEGIN, 100000-BEGIN.length()-END.length(), END);
    
    private static final Pattern CLIENT_IP_PATTERN = Pattern.compile("<client_host_or_ip>(.+?)</client_host_or_ip>");
    
    public static void executeDownloadTest(
            NetSocket lowerLayerNetSocket, long timeoutInMs) throws IOException {
        // communicate with the remote side
        byte[] httpResponse = HttpUtil.getInstance().get(
                lowerLayerNetSocket,
                HTTPTEST_SERVER_NETADDRESS,
                "/httptest/testfile100000bytes.bin",
                timeoutInMs);
        
        // check response
        byte[] expectedResponse = HTTPTEST_TESTFILE_CONTENT_testfile100000bytes;
        assertEquals("wrong http download response length", expectedResponse.length, httpResponse.length); 
        ByteArrayTestUtil.assertEquals("wrong http download response", expectedResponse, httpResponse); 
    }
    
    
    /**
     * Try to execute the /httptest/smalltest.jsp over the provided net socket
     * with a random id.
     * 
     * Closes the socket after the test.
     * 
     * @param lowerLayerNetSocket  this net socket will be closed inside the method
     * @param idPrefix             only digits and ASCII letters, becomes part of the id sent to the server
     * @param timeoutInMs
     * @throws IOException
     */
    public static void executeSmallTest(
            NetSocket lowerLayerNetSocket, String idPrefix, long timeoutInMs) throws IOException {
        boolean testOK = HttpUtil.getInstance().executeSmallTest(lowerLayerNetSocket, idPrefix, timeoutInMs);
        if (!testOK) {
            fail("wrong http response");
        }
    }

    
    /**
     * Create the test file /tmp/testfile100000bytes.bin .
     * 
     * @throws Exception
     */
    public void writeHttpTestFile() throws Exception {
        String FILENAME = "/tmp/testfile100000bytes.bin";
        FileOutputStream file = new FileOutputStream(FILENAME);
        file.write(HTTPTEST_TESTFILE_CONTENT_testfile100000bytes);
        file.close();
    }

    /**
     * Determine the source IP address visible to a public HTTP test server.
     * 
     * @param netLayer             used to create the connection
     * @return the source IP address, not null
     * @throws IOException in the case of an error  
     */
    public static IpNetAddress getSourceIpNetAddress(NetLayer netLayer) throws IOException {
        return getSourceIpNetAddress(netLayer, HttpUtil.HTTPTEST_SERVER_NETADDRESS, "/httptest/bigtest.jsp");
    }
        
    /**
     * Determine the source IP address visible to a public HTTP test server.
     * 
     * A HTTP connection will be established to a public test server
     * that responses with something like "...<client_host_or_ip>1.2.3.4</client_host_or_ip>...".
     * 
     * @param netLayer             used to create the connection
     * @param testAppNetAddress    address to reach the test web application,
     *                             e.g. HttpUtil.HTTPTEST_SERVER_NETADDRESS
     * @param testAppUrlPath       path to reach the test web application,
     *                             e.g. "/httptest/bigtest.jsp"
     * @return the source IP address, not null
     * @throws IOException in the case of an error  
     */
    public static IpNetAddress getSourceIpNetAddress(NetLayer netLayer, TcpipNetAddress testAppNetAddress, String testAppUrlPath) throws IOException {
        // create connection
        NetSocket netSocket = null;

        try {
            // create connection
            netSocket = netLayer.createNetSocket(null, null, testAppNetAddress);
            
            // communicate with the remote side
            byte[] httpResponse = HttpUtil.getInstance().get(
                    netSocket, testAppNetAddress, testAppUrlPath, 10000);
            String httpResponseStr = ByteArrayUtil.showAsString(httpResponse);
            log.fine("http response body: "+ httpResponseStr);
    
            // analyze result
            if (httpResponseStr==null || httpResponseStr.length()<1) {
                throw new IOException("got empty HTTP response");
            }
            Matcher m = CLIENT_IP_PATTERN.matcher(httpResponseStr);
            IpNetAddress clientIp = null; 
            if (m.find()) {
                String clientIpStr = m.group(1);
                try {
                    clientIp = new IpNetAddress(clientIpStr);
                } catch (Exception e) {
                    throw new IOException("invalid source/client IP: "+clientIpStr);
                }
            }
            if (clientIp==null) {
                throw new IOException("could not determine source/client IP");
            }
            return clientIp;
        } finally {
            if (netSocket!=null) {
                netSocket.close();
            }
        }
    }
        
}
