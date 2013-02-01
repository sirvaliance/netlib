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

package org.silvertunnel.netlib.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;

/**
 * This class provides simple methods to access HTTP -
 * they can be used for testing.
 * 
 * The class should not be used in productive environments
 * (because these methods do not handle all edge cases).
 * Consider to use class HttpClient in productive environments.
 *   
 * This method does NOT internally use java.net.URL.
 * 
 * @author hapke
 */
public class HttpUtil {
    private static final Logger log = Logger.getLogger(HttpUtil.class.getName());

    private static final String UTF8 = "UTF-8";
    
    public static final String HTTPTEST_SERVER_NAME = "httptest.silvertunnel.org";
    public static final int HTTPTEST_SERVER_PORT = 80;
    public static final TcpipNetAddress HTTPTEST_SERVER_NETADDRESS =
        new TcpipNetAddress(HTTPTEST_SERVER_NAME, HTTPTEST_SERVER_PORT);

    private static HttpUtil instance = new HttpUtil();
    
    public static HttpUtil getInstance() {
        return instance;
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
     * @return true=test OK; false=test failed
     * @throws IOException
     */
    public boolean executeSmallTest(
            NetSocket lowerLayerNetSocket, String idPrefix, long timeoutInMs) throws IOException {
        // generate the id
        int randomNo = (int)(1000000000*Math.random());
        String id = idPrefix+randomNo;
        
        // communicate with the remote side
        byte[] httpResponse = get(
                lowerLayerNetSocket,
                HttpUtil.HTTPTEST_SERVER_NETADDRESS,
                "/httptest/smalltest.jsp?id="+id,
                timeoutInMs);
        
        // check response
        log.info("http response body: "+ByteArrayUtil.showAsString(httpResponse));
        byte[] expectedResponse = ("<response><id>"+id+"</id></response>\n").getBytes("UTF-8");
        boolean testOK = Arrays.equals(expectedResponse, httpResponse); 
        if (testOK) {
            log.info("http response body = expected response body");
        } else {
            log.info("expected http response body is different: "+ByteArrayUtil.showAsString(expectedResponse));
        }
        
        lowerLayerNetSocket.close();
        
        return testOK;
    }
    
    
    /**
     * Execute a simple HTTP 1.1 request and read the response.
     * 
     * @param lowerNetLayer
     * @param httpServerNetAddress
     * @param pathOnHttpServer
     * @param timeoutInMs    do not wait longer the the specified milliseconds 
     * @return
     * @throws IOException 
     */
    public byte[] get(
            NetLayer lowerNetLayer,
            TcpipNetAddress httpServerNetAddress,
            String pathOnHttpServer,
            long timeoutInMs) throws IOException {
        // open network connection
        NetSocket s = lowerNetLayer.createNetSocket(null, null, httpServerNetAddress);
        
        return get(s, httpServerNetAddress, pathOnHttpServer, timeoutInMs);
    }

    /**
     * Execute a simple HTTP 1.1 request and provide the response body as InputStream.
     * The response header is not part of the returned InputStream.
     * 
     * @param lowerLayer
     * @param httpServerNetAddress
     * @param pathOnHttpServer
     * @param timeoutInMs    do not wait longer the the specified milliseconds 
     * @return the response body
     * @throws IOException 
     */
    public InputStream getReponseBodyInputStream(
            NetSocket lowerLayerNetSocket,
            TcpipNetAddress httpServerNetAddress,
            String pathOnHttpServer,
            long timeoutInMs) throws IOException {
        byte[] responseBody = get(lowerLayerNetSocket, httpServerNetAddress, pathOnHttpServer, timeoutInMs);
        
        return new ByteArrayInputStream(responseBody);
    }    
    
    /**
     * Execute a simple HTTP 1.1 request and read the response.
     * 
     * @param lowerLayer
     * @param httpServerNetAddress
     * @param pathOnHttpServer
     * @param timeoutInMs    do not wait longer the the specified milliseconds 
     * @return the response body
     * @throws IOException 
     */
    public static byte[] get(
            NetSocket lowerLayerNetSocket,
            TcpipNetAddress httpServerNetAddress,
            String pathOnHttpServer,
            long timeoutInMs) throws IOException {
        try {
            String request =
                "GET "+pathOnHttpServer+" HTTP/1.1\n"+
                "Host: "+httpServerNetAddress.getHostnameOrIpaddress()+"\n"+
                // disable keep-alive
                "Connection: close\n"+
                "\n";
            byte[] requestBytes = request.getBytes(UTF8);

            // do the work
            return request(lowerLayerNetSocket, httpServerNetAddress, pathOnHttpServer, requestBytes, timeoutInMs);
        } catch (UnsupportedEncodingException e) {
            log.log(Level.SEVERE, "this exception may never occur", e);
            throw new IOException(e.toString());
        }
    }
    
    /**
     * Execute a simple HTTP 1.1 post and read the response.
     * 
     * @param lowerLayer
     * @param httpServerNetAddress
     * @param pathOnHttpServer
     * @param timeoutInMs    do not wait longer the the specified milliseconds 
     * @return the response body
     * @throws IOException 
     */
    public byte[] post(
            NetSocket lowerLayerNetSocket,
            TcpipNetAddress httpServerNetAddress,
            String pathOnHttpServer,
            byte[] dataToPost,
            long timeoutInMs) throws IOException {
        try {
            String request =
                "POST "+pathOnHttpServer+" HTTP/1.1\r\n"+
                "Host: "+httpServerNetAddress.getHostnameOrIpaddress()+"\r\n"+
                "Content-Type: text/plain; charset=utf-8\r\n"+
                "Content-Length: "+dataToPost.length+"\r\n"+
                // disable keep-alive
                "Connection: close\r\n"+
                "\r\n";
            byte[] requestBytes1 = request.getBytes(UTF8);
            byte[] requestBytes = ByteArrayUtil.concatByteArrays(requestBytes1, dataToPost);

            // TODO - remove?:
            log.info("httpServerNetAddress="+httpServerNetAddress+" with request="+new String(requestBytes, UTF8));

            // do the work
            byte[] response = request(lowerLayerNetSocket, httpServerNetAddress, pathOnHttpServer, requestBytes, timeoutInMs);

            // result
            if (log.isLoggable(Level.FINE)) {
                try {
                    log.info("response="+new String(response, UTF8));
                } catch (Exception e) {
                    log.info("response="+response);
                }
            }

            return response;
        } catch (UnsupportedEncodingException e) {
            log.log(Level.SEVERE, "this exception may never occur", e);
            throw new IOException(e.toString());
        }
    }

    /**
     * Execute a simple HTTP 1.1 get or post request and read the response.
     * 
     * @param lowerLayer
     * @param httpServerNetAddress
     * @param pathOnHttpServer
     * @param timeoutInMs    do not wait longer the the specified milliseconds 
     * @return the response body
     * @throws IOException 
     */
    private static byte[] request(
            NetSocket lowerLayerNetSocket,
            TcpipNetAddress httpServerNetAddress,
            String pathOnHttpServer,
            byte[] requestBytes,
            long timeoutInMs) throws IOException {
        long startTime = System.currentTimeMillis();
        
        // open network connection
        NetSocket s = lowerLayerNetSocket;
        
        // receive HTTP response
        // (start the extra thread before sending the HTTP request
        //  to avoid dead locks in certain circumstances)
        HttpUtilResponseReceiverThread receiverThread =
            new HttpUtilResponseReceiverThread(s.getInputStream());
        
        // send HTTP request
        OutputStream os = s.getOutputStream();
        try {
            log.info("send HTTP request now: "+ByteArrayUtil.showAsString(requestBytes));
            os.write(requestBytes);
        } catch (UnsupportedEncodingException e) {
            log.log(Level.SEVERE, "this exception may never occur", e);
        }
        os.flush();

        receiverThread.start();
        // wait for receiving data
        long millis = Math.max(100, timeoutInMs-(System.currentTimeMillis()-startTime));
        try {
            receiverThread.join(millis);
        } catch (InterruptedException e) {
            // to ignore
        }
        
        // read the HTTP response from the other thread
        byte[] response = receiverThread.readCurrentResultAndStopThread();
        s.close();
        if (log.isLoggable(Level.FINE)) {
            try {
                log.info("response="+new String(response, UTF8));
            } catch (Exception e) {
                log.info("response="+response);
            }
        }
            
        // split response header and body
        int endOfHeaders = response.length;
        int startOfBody = response.length+1;
        for (int i=0; i<response.length; i++) {
            if (i+1<response.length && response[i]=='\n' && response[i+1]=='\n') {
                endOfHeaders= i;
                startOfBody=i+2;
                break;
            } else if (i+3<response.length) {
                if (response[i]=='\n' && response[i+1]=='\r' && response[i+2]=='\n' && response[i+3]=='\r') {
                    endOfHeaders= i;
                    startOfBody=i+4;
                    break;
                } 
                if (response[i]=='\r' && response[i+1]=='\n' && response[i+2]=='\r' && response[i+3]=='\n') {
                    endOfHeaders= i;
                    startOfBody=i+4;
                    break;
                } 
            }
        }
        byte[] responseHeaders = new byte[endOfHeaders];
        if (endOfHeaders>0) {
            System.arraycopy(response, 0, responseHeaders, 0, endOfHeaders);
        }
        int bodyLen = Math.max(0, response.length-startOfBody);
        byte[] responseBody = new byte[bodyLen];
        if (bodyLen>0) {
            System.arraycopy(response, startOfBody, responseBody, 0, bodyLen);
        }
        
        // need to handle chunked HTTP response?
        String responseHeadersAsString = ByteArrayUtil.showAsString(responseHeaders);
        final String CHUNKED_CONTENT_HEADER = "Transfer-Encoding: chunked";
        if (responseHeadersAsString.contains(CHUNKED_CONTENT_HEADER)) {
            // yes: handle chunked response
            responseBody = decodeChunkedHttpResponse(responseBody);
        }
        
        // short log of results
        log.info("received HTTP response header: "+responseHeadersAsString);
        log.info("received HTTP response body of "+responseBody.length+" bytes");
        
        // result
        return responseBody;
    }

    /**
     * Decode a chunked HTTP response
     * 
     * @param chunkedResponse
     * @return the decoded response
     */
    protected static byte[] decodeChunkedHttpResponse(byte[] chunkedResponse) {
        List<Byte> result = new ArrayList<Byte>(chunkedResponse.length);
        StringBuffer chunkLenStr = new StringBuffer();
        for (int i=0; i<chunkedResponse.length;) {
            // end of chunk header?
            int offset = isNewLine(chunkedResponse, i);
            if (offset>0) {
                // yes: end of chunk header
                // convert hex length value to int
                i+=offset;
                final int HEX_RADIX = 16;
                int chunkLength = Integer.parseInt(chunkLenStr.toString(), HEX_RADIX);
                if (chunkLength==0) {
                    // found the end
                    break;
                } else {
                    for (; i<chunkedResponse.length&&chunkLength>0; i++, chunkLength--) {
                        result.add(chunkedResponse[i]);
                    }
                    // prepare collecting the byte of the next chunk header
                    chunkLenStr = new StringBuffer();
                    i+=isNewLine(chunkedResponse, i);
                }
            } else {
                // no: this is part of the chunk header
                chunkLenStr.append((char)chunkedResponse[i++]);
            }
        }
        
        // end reached: convert result
        byte[] decodedChunkedHttpResponse = new byte[result.size()];
        for (int i=0; i<decodedChunkedHttpResponse.length; i++) {
            decodedChunkedHttpResponse[i]=result.get(i);
        }
        return decodedChunkedHttpResponse;
    }
    
    /**
     * Check whether the index points to a 1 or 2 byte long new line
     * 
     * @param data
     * @param index
     * @return 1=1 byte new line; 2=2 byte new lin; 0=no new line in data at position index
     */
    private static int isNewLine(byte[] data, int index) {
        if (index+1<data.length &&
                ((data[index]=='\n' && data[index+1]=='\r') || data[index]=='\r' && data[index+1]=='\n')) {
            // found 2 byte new line
            return 2;
        } else if (index<data.length && data[index]=='\n') {
            // found 1 byte new line
            return 1;
        } else {
            return 0;
        }

    }
   
}
