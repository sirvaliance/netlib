/*
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

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.tor.api.Fingerprint;
import org.silvertunnel.netlib.layer.tor.common.TorConfig;
import org.silvertunnel.netlib.layer.tor.util.Encoding;
import org.silvertunnel.netlib.layer.tor.util.TorException;
import org.silvertunnel.netlib.tool.SimpleHttpClient;
import org.silvertunnel.netlib.util.HttpUtil;


/**
 * Logic to handle Service Descriptors of hidden services.
 * 
 * @see https://www.torproject.org/doc/design-paper/tor-design.html#sec:rendezvous
 * @see http://gitweb.torproject.org/tor.git?a=blob_plain;hb=HEAD;f=doc/spec/rend-spec.txt
 * 
 * @author Andriy
 * @author Lexi
 * @author hapke
 */
public class RendezvousServiceDescriptorService {
    private static final Logger log = Logger.getLogger(RendezvousServiceDescriptorService.class.getName());

    private static RendezvousServiceDescriptorService instance = new RendezvousServiceDescriptorService();
    
    /** service dependency */
    private HttpUtil httpUtil = HttpUtil.getInstance();
    
    /**
     * Number of non-consecutive replicas (i.e. distributed somewhere
     * in the ring) for a descriptor.
     */
    private static final int RENDEZVOUS_NUMBER_OF_NON_CONSECUTIVE_REPLICAS = 2;
    
    public static RendezvousServiceDescriptorService getInstance() {
        return instance;
    }
    
    /**
     * Loads a RendezvousServiceDescriptor from the network.
     * 
     * @param z    the z-part of the address/domain name = rendezvous descriptor service ID
     * @param torConfig
     * @param directory
     * @param torNetLayer    NetLayer to establish stream that goes through Tor network - used to load rendezvous ServiceDescriptor   
     */
    public RendezvousServiceDescriptor loadRendezvousServiceDescriptorFromDirectory(String z, TorConfig torConfig, Directory directory, NetLayer torNetLayer)
    throws IOException {
        String hiddenServicePermanentIdBase32 = z;
        final Date now = new Date();
        final String PRE = "loadRendezvousServiceDescriptorFromDirectory(): ";
       
        int attempts = TorConfig.retriesConnect;
        while(attempts>0) {    
            for (int replica=0; replica<RENDEZVOUS_NUMBER_OF_NON_CONSECUTIVE_REPLICAS; replica++) {
                byte[] descriptorId = RendezvousServiceDescriptorUtil.getRendezvousDescriptorId(hiddenServicePermanentIdBase32, replica, now).getDescriptorId();
                String descriptorIdBase32 = Encoding.toBase32(descriptorId);
                String descriptorIdHex = Encoding.toHexStringNoColon(descriptorId);
                Fingerprint descriptorIdAsFingerprint = new FingerprintImpl(descriptorId);
    
                // try the routers/hidden service directory servers that a responsible for the descriptorId
                Collection<RouterImpl> routers = directory.getThreeHiddenDirectoryServersWithFingerpringGreaterThan(descriptorIdAsFingerprint);
                for (RouterImpl r : routers) {
                    TcpipNetAddress dirAddress = r.getDirAddress();
                    dirAddress = new TcpipNetAddress(dirAddress.getHostnameOrIpaddress()+":"+dirAddress.getPort());
                    log.info(PRE+"try fetching service descriptor for "
                            + z + " with descriptorID base32/hex="+ descriptorIdBase32+"/"+descriptorIdHex
                            +" (with replica="+replica+") from " + r);
 
                    // try to load from one router/hidden service directory server
                    String response = null;
                    try {
                        response = retrieveServiceDescriptor(torNetLayer, dirAddress, descriptorIdBase32);
                    } catch (Exception e) {
                        log.warning(PRE+"unable to connect to or to load data from directory server " + dirAddress + "(" + e.getMessage() + ")");
                        continue;
                    }
    
                    // response: OK
                    if (log.isLoggable(Level.FINE)) {
                        log.fine(PRE+"found descriptorIdBase32="+descriptorIdBase32+" with result(plain)="+response);
                    }
                    try {
                        RendezvousServiceDescriptor result = new RendezvousServiceDescriptor(response, new Date());
                        return result;

                    } catch (TorException e) {
                        log.log(Level.INFO, PRE+"problem parsing Service Descriptor for " + z /*, e*/);
                        continue;
                    }
                }
                --attempts;
            }
        }
        log.warning(PRE+"unable to fetch service descriptor for " + z);
        throw new IOException("unable to fetch service descriptor for " + z);
    }

    /**
     * Save a RendezvousServiceDescriptor in the network, i.e.
     * advertise introduction points of a hidden service.
     * 
     * @param torConfig
     * @param directory
     * @param torNetLayerToConnectToDirectoryService    NetLayer to establish stream that goes through Tor network
     *                                                  - used to save rendezvous ServiceDescriptor  
     * @param hiddenServiceProps
     * @throws IOException
     * @throws TorException
     */
    public void putRendezvousServiceDescriptorToDirectory(TorConfig torConfig, Directory directory,
            final NetLayer torNetLayerToConnectToDirectoryService, HiddenServiceProperties hiddenServiceProps)
    throws IOException, TorException {
        // get the the z-part of the address/domain name
        final String hiddenServicePermanentIdBase32 = RendezvousServiceDescriptorUtil.calculateZFromPublicKey(hiddenServiceProps.getPublicKey());
        final Date now = new Date();
        final String PRE = "putRendezvousServiceDescriptorToDirectory(): ";
        

        // try to post the descriptors
        final AtomicInteger advertiseSuccess = new AtomicInteger(0);
        for (int replica=0; replica<RENDEZVOUS_NUMBER_OF_NON_CONSECUTIVE_REPLICAS; replica++) {
            try {
                final RendezvousServiceDescriptor sd = new RendezvousServiceDescriptor(
                        hiddenServicePermanentIdBase32, replica, now,
                        hiddenServiceProps.getPublicKey(), hiddenServiceProps.getPrivateKey(), hiddenServiceProps.getIntroPoints());
                byte[] descriptorId = sd.getDescriptorId();
                final String descriptorIdBase32 = Encoding.toBase32(descriptorId);
                final String descriptorIdHex = Encoding.toHexStringNoColon(descriptorId);
                Fingerprint descriptorIdAsFingerprint = new FingerprintImpl(descriptorId);
                final int replicaFinal = replica;
                
                // try to post the descriptor to hidden service directory servers that are responsible for the descriptorId -
                // do it in parallel
                Collection<RouterImpl> routers = directory.getThreeHiddenDirectoryServersWithFingerpringGreaterThan(descriptorIdAsFingerprint);
                for (RouterImpl ro : routers) {
                    final RouterImpl r = ro;
                    new Thread() {
                        public void run() {
                            TcpipNetAddress dirAddress = r.getDirAddress();
                            dirAddress = new TcpipNetAddress(dirAddress.getHostnameOrIpaddress()+":"+dirAddress.getPort());
                            log.info(PRE+"try putting service descriptor for "
                                    + hiddenServicePermanentIdBase32 + " with descriptorID base32/hex="+ descriptorIdBase32+"/"+descriptorIdHex
                                    +" (with replica="+replicaFinal+") from " + r);
         
                            // try to post
                            for (int attempts=0; attempts<TorConfig.retriesConnect; attempts++) {
                                try {
                                    postServiceDescriptor(torNetLayerToConnectToDirectoryService, dirAddress, sd);
                                    advertiseSuccess.addAndGet(1);
                                    // finish thread
                                    return;
                                } catch (Exception e) {
                                    log.warning(PRE+"unable to connect to directory server " + dirAddress + "(" + e.getMessage() + ")");
                                    continue;
                                }
                            }
                        }
                    }.start();
                }
            } catch (TorException e1) {
                log.log(Level.WARNING, "unexpected exception", e1);
            }
        }
        
        // wait until timeout or at least one descriptor is posted
        final int TIMEOUT_SECONDS = 120;
        final int MIN_NUMBER_OF_ADVERTISEMENTS = 1;
        for (int seconds=0; seconds<TIMEOUT_SECONDS && advertiseSuccess.get()<MIN_NUMBER_OF_ADVERTISEMENTS; seconds++) {
            // wait a second
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) { /* do nothing */ }
        }
 
        // at least one advertisement?
        if (advertiseSuccess.get() < MIN_NUMBER_OF_ADVERTISEMENTS) {
            throw new TorException("RendezvousServiceDescriptorService: no successful hidden service descriptor advertisement");
        }
    }
    
    /**
     * Retrieve a service descriptor from a directory server via Tor.
     * 
     * @param torNetLayer
     * @param dirNetAddress    address of the directory server
     * @param descriptorIdBase32
     * @return the service descriptor as String
     * @throws IOException
     */
    private String retrieveServiceDescriptor(NetLayer torNetLayer, TcpipNetAddress dirNetAddress, String descriptorIdBase32) throws IOException {
        // download descriptor
        try {
            String path = "/tor/rendezvous2/" + descriptorIdBase32;

            String httpResponse = SimpleHttpClient.getInstance().get(torNetLayer, dirNetAddress, path);
            return httpResponse;

        } catch (Exception e) {
            log.fine("retrieveServiceDescriptor() from " + dirNetAddress + " failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Send a service descriptor to a directory server via Tor.
     * 
     * @param torNetLayerToConnectToDirectoryService
     * @param dirNetAddress                             address of the directory server
     * @param sd                                        the service descriptor to send
     * @throws IOException
     * @throws TorException
     */
    private void postServiceDescriptor(NetLayer torNetLayerToConnectToDirectoryService, TcpipNetAddress dirNetAddress, RendezvousServiceDescriptor sd)
            throws IOException, TorException {
        final String pathOnHttpServer = "/tor/rendezvous2/publish";
        final long timeoutInMs = 60000;

        // send post request and ignore the response:
        NetSocket netSocket = torNetLayerToConnectToDirectoryService.createNetSocket(null, null, dirNetAddress);
        httpUtil.post(netSocket, dirNetAddress, pathOnHttpServer, sd.toByteArray(), timeoutInMs);
    } 
}
