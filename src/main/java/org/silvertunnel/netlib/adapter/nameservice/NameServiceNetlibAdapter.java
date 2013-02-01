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
package org.silvertunnel.netlib.adapter.nameservice;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetAddressNameService;
import org.silvertunnel.netlib.api.util.IpNetAddress;


/**
 * Class that merges the implementations of
 * @see sun.net.spi.nameservice.NameService
 * for Java version 1.5 and 1.6 and higher.
 *
 * @author hapke
 */
class NameServiceNetlibAdapter implements NameServiceNetlibGenericAdapter {
    private static final Logger log = Logger.getLogger(NameServiceNetlibAdapter.class.getName());
    
    private NetAddressNameService netAddressNameService;
    
    /**
     * 
     * @param netAddressNameService    typically a SwicthingNetAddressNameService to be able to change the lower service later.
     */
    NameServiceNetlibAdapter(NetAddressNameService netAddressNameService) {
        this.netAddressNameService = netAddressNameService;
    }
    
    /**
     * @see sun.net.spi.nameservice.NameService#getHostByAddr(byte[])
     */
    public String getHostByAddr(byte[] ip) throws UnknownHostException {
        log.info("getHostByAddr(ip="+Arrays.toString(ip)+")");
        
        // action
        String[] result = netAddressNameService.getNamesByAddress(new IpNetAddress(ip));

        // return single value/best matching result
        return result[0];
    }

    /**
     * @see sun.net.spi.nameservice.NameService#lookupAllHostAddr(java.lang.String)
     * 
     * Attention: This method is needed for Java 1.6 or higher only 
     */
    public InetAddress[] lookupAllHostAddrJava6(String name) throws UnknownHostException {
        log.info("InetAddress[] lookupAllHostAddrJava6(name="+name+")");

        // action
        NetAddress[] result = netAddressNameService.getAddressesByName(name);
        
        // convert result to return format
        InetAddress[] resultFinal = new InetAddress[result.length];
        for (int i=0; i<result.length; i++) {
            resultFinal[i] = ((IpNetAddress)result[i]).getIpaddressAsInetAddress();
        }
        
        return resultFinal;
    }
}
