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

package org.silvertunnel.netlib.nameservice.redirect;

import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetAddressNameService;

/**
 * NetAddressNameService that transparently forwards all traffic to
 * switchable/exchangeable lower NetAddressNameService.
 * 
 * @author hapke
 */
public class SwitchingNetAddressNameService implements NetAddressNameService {
    private static Logger log = Logger.getLogger(SwitchingNetAddressNameService.class.getName());

    /** Currently used lower NetAddressNameService */
    private volatile NetAddressNameService lowerNetAddressNameService;
    
    /**
     * Initialize this name service.
     * 
     * @param name2AddressMapping    mapping used by method getAddresses();
     *                               Map, keys and values may not be null
     * @param address2NameMapping    mapping used by method getNames();
     *                               Map, keys and values may not be null
     */
    public SwitchingNetAddressNameService(Map<String,NetAddress> name2AddressMapping, Map<NetAddress,String> address2NameMapping) {
    }

    /**
     * Start with the provided lowerNetAddressNameService.
     * The lowerNetAddressNameService can be exchanged later by calling the method setLowerNetAddressNameService().
     * 
     * @param lowerNetLayer
     */
    public SwitchingNetAddressNameService(NetAddressNameService lowerNetAddressNameService) {
        this.lowerNetAddressNameService = lowerNetAddressNameService;
    }

    /**
     * Exchange the lower NetAddressNameService.
     * 
     * @param lowerNetAddressNameService    new lower NetAddressNameService
     */
    public void setLowerNetAddressNameService(NetAddressNameService lowerNetAddressNameService) {
        this.lowerNetAddressNameService = lowerNetAddressNameService;
    }

    
        
    /** @see NetAddressNameService#getAddresses */
    public NetAddress[] getAddressesByName(String name) throws UnknownHostException {
        // forward to the lower NetAddressNameService
        return lowerNetAddressNameService.getAddressesByName(name);
    }

    /** @see NetAddressNameService#getNames */
    public String[] getNamesByAddress(NetAddress address) throws UnknownHostException {
        // forward to the lower NetAddressNameService
        return lowerNetAddressNameService.getNamesByAddress(address);
    }
}
