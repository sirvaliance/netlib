/**
 * OnionCoffee - Anonymous Communication through TOR Network
 * Copyright (C) 2005-2007 RWTH Aachen University, Informatik IV
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
package org.silvertunnel.netlib.layer.tor.common;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.tor.api.Fingerprint;

/**
 * Compound data structure.
 * 
 * @author Lexi Pimenidis
 * @author Andriy Panchenko
 */
public class TCPStreamProperties {
    private static final Logger log = Logger.getLogger(TCPStreamProperties.class.getName());

    private String hostname;
    private InetAddress addr;
    /** set to true, if hostname is resolved into addr */
    private boolean addrResolved;
    /** allow exit servers to be untrusted */
    private boolean untrustedExitAllowed = true;
    /** allow entry node to be non Guard (dirv2) */
    private boolean nonGuardEntryAllowed = true;
    private boolean exitPolicyRequired = true;
    private int port;
    private int routeMinLength;
    private int routeMaxLength;
    private int connectRetries;
    /** 
     * p = [0..1]
     * 0 -> select hosts completely randomly
     * 1 -> select hosts with good uptime/bandwidth with higher prob.
     */
    private float p; 
    private Fingerprint[] route;


    /**
     * preset the data structure with all necessary attributes
     * 
     * @param host
     *            give a hostname
     * @param port
     *            connect to this port
     */
    public TCPStreamProperties(String host, int port) {
        this.hostname = host;
        this.port = port;
        addrResolved = false;

        init();
    }
    
    public TCPStreamProperties(InetAddress addr, int port) {
        this.hostname = addr.getHostAddress();
        this.addr = addr;
        this.port = port;
        addrResolved = true;

        init();
    }

    public TCPStreamProperties(TcpipNetAddress address) {
           if (address.getIpaddress()!=null) {
            // use IP address (preferred over host name)
            this.hostname = null;
            try {
                this.addr = InetAddress.getByAddress(address.getIpaddress());
            } catch (UnknownHostException e) {
                log.log(Level.WARNING, "invalid address="+address, e);
            }

            this.port = address.getPort();
            addrResolved = true;

        } else {
            // use host name
            this.hostname = address.getHostname();
            this.addr = null;
            this.port = address.getPort();
            addrResolved = false;
        }

        init();
    }

    public TCPStreamProperties() {
        this.hostname = null;
        this.addr = null;
        this.port = 0;
        addrResolved = false;

        init();
    }
    
    /** Default initialization of member variables **/
    private void init() {
        routeMinLength = TorConfig.routeMinLength;
        routeMaxLength = TorConfig.routeMaxLength;
        p = 1;
        connectRetries = TorConfig.retriesStreamBuildup;
    }


    /**
     * sets predefined route
     * 
     * @param route    custom route (Fingerprints of the routers)
     */
    public void setCustomRoute(Fingerprint[] route) {
        this.route = route;
    }

    /** 
     * sets this node as a predefined exit-point 
     * 
     * @param node    Fingerprint of the predefined exit-point router
     */
    public void setCustomExitpoint(Fingerprint node) {
        if (route == null) {
            routeMinLength = routeMaxLength;
            route = new Fingerprint[routeMaxLength];
        }
        route[route.length-1] = node;
    }
    
    /**
     * @return predefined route
     * 
     */
    public Fingerprint[] getProposedRouteFingerprints() {
        return route;
    }

        /**
     * returns hostname if set, in another case the IP
     * 
     */
    public String getDestination() {
        if (hostname.length() > 0) {
            return hostname;
        }
        return addr.getHostAddress();
    }

    
    ///////////////////////////////////////////////////////
    // generated getters and setters
    ///////////////////////////////////////////////////////
    
    /**
     * @return p = [0..1]
     *   0 -> select hosts completely randomly
     *   1 -> select hosts with good uptime/bandwidth with higher prob.
     */
    public float getRankingInfluenceIndex() {
        return p;
    }

    /**
     * @param p = [0..1]
     *   0 -> select hosts completely randomly
     *   1 -> select hosts with good uptime/bandwidth with higher prob.
     */
    public void setRankingInfluenceIndex(float p) {
        this.p = p;
    }

    /**
     * set minimum route length
     * 
     * @param min
     *            minimum route length
     */
    public void setMinRouteLength(int min) {
        if (min >= 0)
            routeMinLength = min;
    }

    /**
     * set maximum route length
     * 
     * @param max
     *            maximum route length
     */
    public void setMaxRouteLength(int max) {
        if (max >= 0)
            routeMaxLength = max;
    }

    /**
     * get minimum route length
     * 
     * @return minimum route length
     */
    public int getMinRouteLength() {
        return routeMinLength;
    }

    /**
     * get maximum route length
     * 
     * @return maximum route length
     */
    public int getMaxRouteLength() {
        return routeMaxLength;
    }

    public String getHostname() {
        return hostname;
    }

    public void setAddr(InetAddress addr) {
        this.addr = addr;
    }

    public InetAddress getAddr() {
        return addr;
    }

    public boolean isAddrResolved() {
        return addrResolved;
    }

    public void setAddrResolved(boolean addrResolved) {
        this.addrResolved = addrResolved;
    }

    public boolean isUntrustedExitAllowed() {
        return untrustedExitAllowed;
    }

    public void setUntrustedExitAllowed(boolean untrustedExitAllowed) {
        this.untrustedExitAllowed = untrustedExitAllowed;
    }

    public boolean isNonGuardEntryAllowed() {
        return nonGuardEntryAllowed;
    }

    public void setNonGuardEntryAllowed(boolean nonGuardEntryAllowed) {
        this.nonGuardEntryAllowed = nonGuardEntryAllowed;
    }

    public boolean isExitPolicyRequired() {
        return exitPolicyRequired;
    }

    public void setExitPolicyRequired(boolean exitPolicyRequired) {
        this.exitPolicyRequired = exitPolicyRequired;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public int getRouteMinLength() {
        return routeMinLength;
    }

    public void setRouteMinLength(int routeMinLength) {
        this.routeMinLength = routeMinLength;
    }

    public int getRouteMaxLength() {
        return routeMaxLength;
    }

    public void setRouteMaxLength(int routeMaxLength) {
        this.routeMaxLength = routeMaxLength;
    }

    public int getConnectRetries() {
        return connectRetries;
    }

    public void setConnectRetries(int connectRetries) {
        this.connectRetries = connectRetries;
    }

    public float getP() {
        return p;
    }

    public void setP(float p) {
        this.p = p;
    }
    
    public Fingerprint[] getRouteFingerprints() {
        return route;
    }
}
