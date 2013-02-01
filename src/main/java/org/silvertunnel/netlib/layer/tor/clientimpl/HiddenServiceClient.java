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
package org.silvertunnel.netlib.layer.tor.clientimpl;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.layer.tor.api.Fingerprint;
import org.silvertunnel.netlib.layer.tor.circuit.CellRelay;
import org.silvertunnel.netlib.layer.tor.circuit.CellRelayEstablishRendezvous;
import org.silvertunnel.netlib.layer.tor.circuit.CellRelayIntroduce1;
import org.silvertunnel.netlib.layer.tor.circuit.Circuit;
import org.silvertunnel.netlib.layer.tor.circuit.CircuitAdmin;
import org.silvertunnel.netlib.layer.tor.circuit.Node;
import org.silvertunnel.netlib.layer.tor.circuit.TLSConnectionAdmin;
import org.silvertunnel.netlib.layer.tor.common.TCPStreamProperties;
import org.silvertunnel.netlib.layer.tor.common.TorConfig;
import org.silvertunnel.netlib.layer.tor.common.TorEventService;
import org.silvertunnel.netlib.layer.tor.directory.Directory;
import org.silvertunnel.netlib.layer.tor.directory.RendezvousServiceDescriptor;
import org.silvertunnel.netlib.layer.tor.directory.RendezvousServiceDescriptorService;
import org.silvertunnel.netlib.layer.tor.directory.RouterImpl;
import org.silvertunnel.netlib.layer.tor.directory.SDIntroductionPoint;
import org.silvertunnel.netlib.layer.tor.stream.TCPStream;
import org.silvertunnel.netlib.layer.tor.util.Encoding;
import org.silvertunnel.netlib.layer.tor.util.TorException;

public class HiddenServiceClient {
    private static final Logger log = Logger.getLogger(HiddenServiceClient.class.getName());
 
    /**
     * key:   z part of the domain name= rendezvous service id
     * value: RendezvousServiceDescriptor
     */
    private static Map<String,RendezvousServiceDescriptor> cachedRendezvousServiceDescriptors = new HashMap<String, RendezvousServiceDescriptor>();
    
    private static RendezvousServiceDescriptorService rendezvousServiceDescriptorService = RendezvousServiceDescriptorService.getInstance();
    
    /**
     * makes a connection to a hidden service
     * 
     * @param torConfig             tor environment
     * @param directory             tor environment
     * @param torEventService       tor environment
     * @param tlsConnectionAdmin    tor environment
     * @param torNetLayer           tor environment
     * @param spo                   connection destination
     * @return
     * @throws IOException
     */
    static TCPStream connectToHiddenService(TorConfig torConfig, Directory directory, TorEventService torEventService, TLSConnectionAdmin tlsConnectionAdmin,
            NetLayer torNetLayer, TCPStreamProperties spo) throws IOException {
        // String address, x, y;
        String z = Encoding.parseHiddenAddress(spo.getHostname()).get("z");

        //
        // get a copy from the rendezvous service descriptor
        //
        RendezvousServiceDescriptor sd = (RendezvousServiceDescriptor) cachedRendezvousServiceDescriptors.get(z);
        if (sd == null || (!sd.isPublicationTimeValid(new Date()))) {
            // no valid entry in cache: retrieve a fresh one
            sd = rendezvousServiceDescriptorService.loadRendezvousServiceDescriptorFromDirectory(z, torConfig, directory, torNetLayer);
            // cache it
            cachedRendezvousServiceDescriptors.put(z, sd);
        }
        if (sd==null) {
            throw new IOException("connectToHiddenService(): couldn't retrieve RendezvousServiceDescriptor for z=" + z);
        }
        log.info("connectToHiddenService(): use RendezvousServiceDescriptor="+sd);

        //
        // action
        //
        boolean establishedRendezvousPoint = false;
        boolean connectedToIntroPoint = false;
        boolean didRendezvous = false;
        for (int attempts=0; attempts<spo.getConnectRetries(); attempts++) {
            Circuit rendezvousPointCircuit = null;
            try {
                //
                // establish a rendezvous point (section 1.7 of Tor Rendezvous Specification)
                //
                RendezvousPointData rendezvousPointData = null;
                rendezvousPointData = createRendezvousPoint(directory, torEventService, tlsConnectionAdmin, z);
                rendezvousPointCircuit = rendezvousPointData.getMyRendezvousCirc();
                rendezvousPointCircuit.setServiceDescriptor(sd);
                establishedRendezvousPoint = true;
                log.info("connectToHiddenService(): use circuit to rendezvous point=" + rendezvousPointData.getMyRendezvousCirc());

                //
                // Introduction: from Alice's OP to Introduction Point (section 1.8 of Tor Rendezvous Specification)
                //
                for (SDIntroductionPoint introPoint : sd.getIntroductionPoints()) {
                    Node introPointServicePublicKeyNode = sendIntroduction1Cell(torConfig, directory, torEventService, tlsConnectionAdmin, rendezvousPointData, introPoint, z);
                    connectedToIntroPoint = true;
                    
                    //
                    // Rendezvous (section 1.10 of Tor Rendezvous Specification)
                    //
                    doRendezvous(rendezvousPointCircuit, introPointServicePublicKeyNode, z);
                    didRendezvous = true;
                    
                    //
                    // Creating stream(s) (section 1.11 of Tor Rendezvous Specification)
                    //

                    // connect - with empty address in begin cell set
                    final String hiddenServiceExternalAddress = "";
                    TCPStreamProperties tcpProps = new TCPStreamProperties(hiddenServiceExternalAddress, spo.getPort());
                    return new TCPStream(rendezvousPointCircuit, tcpProps);
                }
            } catch (Exception e) {
                log.log(Level.INFO, ""+e);
                // release resources
                if (rendezvousPointCircuit!=null) {
                    rendezvousPointCircuit.close(true);
                    rendezvousPointCircuit = null;
                }
            } finally {
                // set flage for later release of resources
                if (rendezvousPointCircuit!=null) {
                    rendezvousPointCircuit.setCloseCircuitIfLastStreamIsClosed(true);
                }
            }
        }
            
        //
        // error occurred - send suitable error messages
        //
        String msg;
        if (!establishedRendezvousPoint) {
            msg = "connectToHiddenService(): coudn't establishing rendezvous point for " + z;
        } else if (!connectedToIntroPoint) {
            msg = "connectToHiddenService(): couldn't connect to an introduction point of " + z;
        } else if (!didRendezvous) {
            msg = "connectToHiddenService(): oudn't make a rendezvous for " + z;
        } else {
            msg = "connectToHiddenService(): couldn't connect to remote server of " + z;
        }
        log.warning(msg);
        throw new IOException(msg);
    }


    /**
     * Establish a circuit to a new rendezvous point.
     * 
     * "establish a rendezvous point (section 1.7 of Tor Rendezvous Specification)"
     * 
     * @param directory
     * @param torEventService
     * @param tlsConnectionAdmin
     * @param z
     * @return the rendezvous point; not null
     * @throws IOException 
     * @throws TorException 
     */
    private static RendezvousPointData createRendezvousPoint(Directory directory, TorEventService torEventService, TLSConnectionAdmin tlsConnectionAdmin, String z)
            throws IOException, TorException {
        Circuit myRendezvousCirc = null;
        try {
            myRendezvousCirc = CircuitAdmin.provideSuitableExclusiceCircuit(
                tlsConnectionAdmin, directory, new TCPStreamProperties(), torEventService);
            if (myRendezvousCirc==null) {
                throw new TorException("getNewRendezvousPoint(): couldnt establish rendezvous point for " + z +" - at the moment");
            }
            RouterImpl rendezvousPointRouter = myRendezvousCirc.getRouteNodes()[myRendezvousCirc.getRouteEstablished()-1].getRouter();
    
            log.info("getNewRendezvousPoint(): establishing rendezvous point for " + z + " at "+ rendezvousPointRouter);
            Random rnd = new Random();
            byte[] rendezvousCookie = new byte[20]; 
            rnd.nextBytes(rendezvousCookie);
    
            myRendezvousCirc.sendCell(new CellRelayEstablishRendezvous( myRendezvousCirc, rendezvousCookie));
            // TODO: not needed?
            //myRendezvousCirc.getStreamHistory().add(spo.getHostname());
    
            // wait for answer
            CellRelay rendezvousACK = myRendezvousCirc.getQueue().receiveRelayCell(CellRelay.RELAY_RENDEZVOUS_ESTABLISHED);
            if (rendezvousACK.getLength() > 0) {
                throw new TorException("connectToHiddenService(): Got NACK from RENDEZVOUS Point");
            }
            
            // success
            log.info("getNewRendezvousPoint(): establishing rendezvous point for " + z + " at "+ rendezvousPointRouter);
            return new RendezvousPointData(rendezvousCookie, rendezvousPointRouter, myRendezvousCirc);
        } catch (IOException e) {
            if (myRendezvousCirc!=null) {
                myRendezvousCirc.close(true);
            }
            throw e;
        } catch (TorException e) {
            if (myRendezvousCirc!=null) {
                myRendezvousCirc.close(true);
            }
            throw e;
        }
    }
    
    /**
     * Send introduction1 cell
     * 
     * "Introduction: from Alice's OP to Introduction Point (section 1.8 of Tor Rendezvous Specification)"
     * 
     * @param torConfig
     * @param directory
     * @param torEventService
     * @param tlsConnectionAdmin
     * @param rendezvousPointData
     * @param introPoint             send the introduction1 cell to this introPoint
     * @param z
     * @return introPointServicePublicKeyNode; not null
     * @throws IOException
     * @throws TorException
     * @throws InterruptedException
     */
    private static Node sendIntroduction1Cell(TorConfig torConfig, Directory directory, TorEventService torEventService, TLSConnectionAdmin tlsConnectionAdmin,
            RendezvousPointData rendezvousPointData, SDIntroductionPoint introPoint, String z)
            throws IOException, TorException, InterruptedException {

        Fingerprint introPointFingerprint = introPoint.getIdentifierAsFingerprint();
        log.info("sendIntroduction1Cell(): contacting introduction point=" + introPointFingerprint + " for " + z);

        // build new circuit where the last node is introduction point
        TCPStreamProperties spIntro = new TCPStreamProperties();
        spIntro.setExitPolicyRequired(false);
        spIntro.setCustomExitpoint(introPointFingerprint);
        Circuit myIntroCirc = null;
        try {
            myIntroCirc = new Circuit(tlsConnectionAdmin, directory, spIntro, torEventService);

            log.info("sendIntroduction1Cell(): use Circuit to introduction point="+myIntroCirc);
    
            // send CellIntro1 data encrypted with PK of the introPoint
            RouterImpl introPointServicePublicKey = new RouterImpl(torConfig, introPoint.getServicePublicKey());
            Node introPointServicePublicKeyNode = new Node(introPointServicePublicKey); 
            myIntroCirc.sendCell(new CellRelayIntroduce1(
                    myIntroCirc, rendezvousPointData.getRendezvousCookie(), introPoint, introPointServicePublicKeyNode, rendezvousPointData.getRendezvousPointRouter()));
    
            // wait for ack
            CellRelay introACK = myIntroCirc.getQueue().receiveRelayCell(CellRelay.RELAY_COMMAND_INTRODUCE_ACK);
            if (introACK.getLength() > 0) {
                throw new TorException("sendIntroduction1Cell(): Got NACK from Introduction Point introACK="+introACK);
            }
            // introduce ACK is received
            log.info("sendIntroduction1Cell(): Got ACK from Intro Point");

            return introPointServicePublicKeyNode;

        } finally {
            // close the circuit: not needed anymore
            if (myIntroCirc!=null) {
                myIntroCirc.close(true);
            }
        }
        
    }
    
    /**
     * Implementation of the rendezvous.
     * 
     * "Rendezvous (section 1.10 of Tor Rendezvous Specification)"
     * 
     * @param myRendezvousCircuit               try to rendezvous here
     * @param introPointServicePublicKeyNode
     * @param z
     * @throws TorException
     * @throws IOException
     */
    private static void doRendezvous(Circuit myRendezvousCircuit, Node introPointServicePublicKeyNode, String z) throws TorException, IOException{
        // wait for answer from the hidden service (RENDEZVOUS2)
        int oldTimeout = myRendezvousCircuit.getQueue().getTimeoutMs();
        if (oldTimeout < 120*1000) {
            myRendezvousCircuit.getQueue().setTimeoutMs(120*1000);
        }
        CellRelay r2Relay = myRendezvousCircuit.getQueue().receiveRelayCell(CellRelay.RELAY_RENDEZVOUS2);
        myRendezvousCircuit.getQueue().setTimeoutMs(oldTimeout);
        // finish Diffie-Hellman
        byte[] dhGy = new byte[148];
        System.arraycopy(r2Relay.getData(), 0, dhGy, 0, 148);
        introPointServicePublicKeyNode.finishDh(dhGy);

        myRendezvousCircuit.addNode(introPointServicePublicKeyNode);

        log.info("doRendezvous(): succesfully established rendezvous with " + z);
    }
}
