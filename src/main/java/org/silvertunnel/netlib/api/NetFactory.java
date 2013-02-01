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

import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Manage a repository of NetLayer objects.
 * 
 * @author hapke
 */
public class NetFactory implements NetLayerFactory {
    private static final Logger log = Logger.getLogger(NetFactory.class.getName());

    public static final String NETFACTORY_MAPPING_PROPERTIES = "/org/silvertunnel/netlib/api/netfactory_mapping.properties";
    
    /** repository cache */
    private Map<String,NetLayer> netLayerRepository = new HashMap<String,NetLayer>();

    private static NetFactory instance = new NetFactory();
    
    public static NetFactory getInstance() {
        return instance;
    }
    
    public synchronized void registerNetLayer(String netLayerId, NetLayer netLayer) {
        netLayerRepository.put(netLayerId, netLayer);
        log.info("registerNetLayer with netLayerId="+netLayerId);
    }
    
    /**
     * @see NetLayerFactory#getNetLayerById(String)
     */
    public synchronized NetLayer getNetLayerById(String netLayerId) {
        NetLayer result = netLayerRepository.get(netLayerId);
        if (result==null) {
            // not yet in cache: try to instantiate
            try {
                NetLayerFactory factory = getNetLayerFactoryByNetLayerID(netLayerId);
                if (factory!=null) {
                    result = factory.getNetLayerById(netLayerId);
                    if (result!=null) {
                        // store in cache
                        registerNetLayer(netLayerId, result);
                    }
                }

            } catch (Exception e) {
                log.log(Level.SEVERE, "could not create NetLayer of "+netLayerId, e);
            }
        }
        
        return result;
    }
    
    /**
     * Load class based on mapping properties.
     * 
     * @param netLayerId
     * @return null if not found
     */
    private NetLayerFactory getNetLayerFactoryByNetLayerID(String netLayerId) {
        try {
            // load properties, read class factory name
            InputStream in = getClass().getResourceAsStream(NETFACTORY_MAPPING_PROPERTIES);
            Properties mapping = new Properties();
            mapping.load(in);

            String netLayerFactoryClassName = mapping.getProperty(netLayerId);
            
            // try to load NetLayerFactory
            Class<?> clazz = Class.forName(netLayerFactoryClassName);
            Constructor<?> c = clazz.getConstructor();
            NetLayerFactory result = (NetLayerFactory)c.newInstance();
            
            return result;
            
        } catch (Exception e) {
            log.log(Level.SEVERE, "could not create NetLayerFactory of "+netLayerId, e);
            return null;
        }
    }
}
