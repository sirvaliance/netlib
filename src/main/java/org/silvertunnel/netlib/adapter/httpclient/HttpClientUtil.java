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

package org.silvertunnel.netlib.adapter.httpclient;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.util.HttpUtil;


/**
 * Adapter to Apache HttpClient 4.x.
 * 
 * This is still very EXPERIMENTAL - not for serious use!!!
 * 
 * This code is currently not used and not needed outside of package
 * org.silvertunnel.netlib.adapter.httpclient
 * 
 * @author hapke
 */
public class HttpClientUtil {
    private static final Logger log = Logger.getLogger(HttpClientUtil.class.getName());

    private static SchemeRegistry supportedSchemes;
    private static ClientConnectionManager connMgr;
    private static HttpParams params = new BasicHttpParams();
    
    private static NetLayer lowerNetLayer;
    
    // init
    static void init(NetLayer lowerNetLayer) {
        try {
            HttpClientUtil.lowerNetLayer = lowerNetLayer;
            Scheme http = new Scheme("http", new NetlibSocketFactory(lowerNetLayer), 80);

            supportedSchemes = new SchemeRegistry();
            supportedSchemes.register(http);


            // prepare parameters
            HttpParams params = new BasicHttpParams();
            HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
            HttpProtocolParams.setContentCharset(params, "UTF-8");
            HttpProtocolParams.setUseExpectContinue(params, true);

            connMgr = new ThreadSafeClientConnManager(params, supportedSchemes);

        } catch (Exception e) {
            log.log(Level.SEVERE, "error during class init", e);
        }
    }
    
    public static InputStream simpleAction(URL url) throws IOException {
        int port = (url.getPort()<0) ? 80 : url.getPort();
        TcpipNetAddress httpServerNetAddress = new TcpipNetAddress(url.getHost(), port);
        Map<String,Object> localProperties = new HashMap<String,Object>();
        NetSocket lowerLayerNetSocket = lowerNetLayer.createNetSocket(localProperties, /*localAddress*/ null, httpServerNetAddress);
        String pathOnHttpServer = url.getPath();
        if (pathOnHttpServer==null || pathOnHttpServer.length()<1) {
            pathOnHttpServer = "/";
        }
        long timeoutInMs = 10L*1000L;
        
        return HttpUtil.getInstance().getReponseBodyInputStream(
                lowerLayerNetSocket,
                httpServerNetAddress,
                pathOnHttpServer,
                timeoutInMs);
    }

    public static byte[] simpleBytesAction(URL url) throws IOException {
        int port = (url.getPort()<0) ? 80 : url.getPort();
        TcpipNetAddress httpServerNetAddress = new TcpipNetAddress(url.getHost(), port);
        Map<String,Object> localProperties = new HashMap<String,Object>();
        NetSocket lowerLayerNetSocket = lowerNetLayer.createNetSocket(localProperties, /*localAddress*/ null, httpServerNetAddress);
        String pathOnHttpServer = url.getPath();
        if (pathOnHttpServer==null || pathOnHttpServer.length()<1) {
            pathOnHttpServer = "/";
        }
        long timeoutInMs = 10L*1000L;
        
        return HttpUtil.getInstance().get(
                lowerLayerNetSocket,
                httpServerNetAddress,
                pathOnHttpServer,
                timeoutInMs);
    }
    
    
    private static InputStream action_NOT_NEEDED(URL url) throws IOException {
        
        HttpHost target = new HttpHost(url.getHost(), url.getPort(), url.getProtocol());

        DefaultHttpClient httpclient = new DefaultHttpClient(connMgr, params);

        HttpGet req = new HttpGet(url.getPath());

        log.info("executing request to " + target);

        HttpResponse rsp = httpclient.execute(target, req);
        HttpEntity entity = rsp.getEntity();
        /*
        if (entity != null) {
            log.info(EntityUtils.toString(entity));
        }
        */
        return entity.getContent();

        
        // When HttpClient instance is no longer needed, 
        // shut down the connection manager to ensure
        // immediate deallocation of all system resources
 
        //TODO: httpclient.getConnectionManager().shutdown();        

    }
}
