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

package org.silvertunnel.netlib.layer.tor.directory;

import org.silvertunnel.netlib.layer.tor.api.RouterExitPolicy;
import org.silvertunnel.netlib.layer.tor.util.Encoding;

/**
 * Compound data structure for storing exit policies.
 * 
 * An object is read-only.
 * 
 * @author hapke
 */
public class RouterExitPolicyImpl implements RouterExitPolicy, Cloneable {
    /** if false: reject */
    private boolean accept;
    private long ip;
    private long netmask;
    private int loPort;
    private int hiPort;
    
    public RouterExitPolicyImpl(boolean accept, long ip, long netmask, int loPort, int hiPort) {
        this.accept = accept;
        this.ip = ip;
        this.netmask = netmask;
        this.loPort = loPort;
        this.hiPort = hiPort;
    }
    
    /**
     * Clone, but do not throw an exception.
     */
    public RouterExitPolicy cloneReliable() throws RuntimeException {
        try {
            return (RouterExitPolicy)clone();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }
    
    @Override
    public String toString() {
        return accept + " "
                + Encoding.toHex(ip) + "/"
                + Encoding.toHex(netmask) + ":"
                + loPort + "-" + hiPort;
    }
    
    ///////////////////////////////////////////////////////
    // generated getters
    ///////////////////////////////////////////////////////

    public boolean isAccept() {
        return accept;
    }

    public long getIp() {
        return ip;
    }

    public long getNetmask() {
        return netmask;
    }

    public int getLoPort() {
        return loPort;
    }

    public int getHiPort() {
        return hiPort;
    }
}
