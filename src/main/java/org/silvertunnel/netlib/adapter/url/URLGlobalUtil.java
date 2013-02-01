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

package org.silvertunnel.netlib.adapter.url;

import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.adapter.url.impl.net.http.HttpHandler;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.layer.tcpip.TcpipNetLayer;
import org.silvertunnel.netlib.layer.tls.TLSNetLayer;

/**
 * This class allows modification of the JVM global URL handling.
 * 
 * Detailed description: http://sourceforge.net/apps/trac/silvertunnel/wiki/NetlibAdapterURL 
 * 
 * @author hapke
 */
public class URLGlobalUtil {
    private static final Logger log = Logger.getLogger(URLGlobalUtil.class.getName());

    private static NetlibURLStreamHandlerFactory netlibURLStreamHandlerFactory;
    
    /**
     * Initialize the URLStreamHandlerFactory of class java.net.URL.
     * 
     * The first lower NetLayer is {@link NopNetLayer}
     * and NOT {@link TcpipNetLayer}/{@link TLSNetLayer}
     * i.e. all requests will fail
     * (and do NOT behave, from the user perspective, as before calling this method).
     * 
     * This method call influences the complete Java JVM.
     * 
     * This method can be called multiple times without any problems,
     * but URL.setURLStreamHandlerFactory() may not be called before the
     * first call of this method to avoid problems.
     */
    public static synchronized void initURLStreamHandlerFactory() {
        NetLayer tcpipNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.NOP); 
        NetLayer tlsNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.NOP); 
        NetlibURLStreamHandlerFactory factory = new NetlibURLStreamHandlerFactory(tcpipNetLayer, tlsNetLayer, false);

        initURLStreamHandlerFactory(factory);
    }
    /**
     * Initialize the URLStreamHandlerFactory of class java.net.URL.
     * 
     * This method call influences the complete Java JVM.
     * 
     * This method can be called multiple times without any problems,
     * but URL.setURLStreamHandlerFactory() may not be called before the
     * first call of this method to avoid problems.
     * 
     * @param factory    use this factory if possible 
     */
    public static synchronized void initURLStreamHandlerFactory(NetlibURLStreamHandlerFactory factory) {
        //
        // preparation of the work
        //
        
        // Avoid java.lang.ClassCircularityError: org/silvertunnel/netlib/adapter/url/impl/net/http/HttpURLConnection$StreamingOutputStream
        //       (details on https://sourceforge.net/apps/trac/silvertunnel/ticket/114)
        //
        // This is really a hack
        // because it only avoids a specific the Java Web Start problem of the silvertunnel.org Browser
        try {
            // load the class HttpURLConnection.StreamingOutputStream early(=here)
            new HttpHandler(null).openConnection(null, null);
        } catch (Exception e) {
            log.log(Level.FINE, "Can be ignored be ignored", e);
        }


        //
        // do the work
        //
        if (netlibURLStreamHandlerFactory==null) {
            try {
                netlibURLStreamHandlerFactory = factory;
                URL.setURLStreamHandlerFactory(factory);

            } catch (Throwable e) {
                String msg =
                    "URL.setURLStreamHandlerFactory() was already called before,"+
                    " but not from UrlUtil, i.e. maybe the wrong factory is set";
                if (log.isLoggable(Level.FINE)) {
                    log.log(Level.WARNING, msg+": "+e, e);
                } else {
                    log.log(Level.WARNING, msg+": "+e);
                }
            }
        }
    }
    
    /**
     * Set a new NetLayer that will be used by the URLStreamHandlerFactory inside java.net.URL.
     * 
     * This method call influences the complete Java JVM.
     * 
     * @param tcpipNetLayer    TcpipNetLayer compatible layer used for http;
     *                         if null then prevent network connections
     * @param tlsNetLayer      TLSNetLayer compatible layer used for https;
     *                         if null then prevent network connections
     * @throws IllegalStateException if initURLStreamHandlerFactory() was not called before calling this method
     */
    public static synchronized void setNetLayerUsedByURLStreamHandlerFactory(NetLayer tcpipNetLayer, NetLayer tlsNetLayer) throws IllegalStateException {
        if (netlibURLStreamHandlerFactory==null) {
            throw new IllegalStateException("initURLStreamHandlerFactory() must be called first (but was not)");
        }
            
        // action
        netlibURLStreamHandlerFactory.setNetLayerForHttpHttpsFtp(tcpipNetLayer, tlsNetLayer);
    }
    
    /**
     * Set a new common NetLayer which is used for protocols http, https (maybe in the future: and ftp). 
     * 
     * @param tcpipNetLayer    TcpipNetLayer compatible layer used for http;
     *                         on top of this layer a TLSNetLayer will be created for https;
     *                         if null then prevent network connections
     * @throws IllegalStateException if initURLStreamHandlerFactory() was not called before calling this method
     */
    public static synchronized void setNetLayerUsedByURLStreamHandlerFactory(NetLayer tcpipNetLayer) throws IllegalStateException {
        setNetLayerUsedByURLStreamHandlerFactory(tcpipNetLayer, new TLSNetLayer(tcpipNetLayer));
    }
}
