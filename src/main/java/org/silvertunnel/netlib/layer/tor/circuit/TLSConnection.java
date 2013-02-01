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
package org.silvertunnel.netlib.layer.tor.circuit;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManager;

import org.silvertunnel.netlib.api.NetAddress;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetSocket;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.tls.TLSNetLayer;
import org.silvertunnel.netlib.layer.tor.common.TorX509TrustManager;
import org.silvertunnel.netlib.layer.tor.directory.RouterImpl;
import org.silvertunnel.netlib.layer.tor.util.PrivateKeyHandler;
import org.silvertunnel.netlib.layer.tor.util.TorException;


/**
 * functionality for the TLS connections bridging the gap to the first nodes in
 * the routes.
 * 
 * @author Lexi Pimenidis
 * @author Vinh Pham
 * @author hapke
 */
public class TLSConnection {
    private static final Logger log = Logger.getLogger(TLSConnection.class.getName());

    private static final String enabledSuitesStr = "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_DHE_RSA_WITH_AES_128_CBC_SHA";

    /** pointer to the server/router */
    private RouterImpl router;
    /** the physical connection (if any) to the node */
    private NetSocket tls;
    private boolean closed = false;
    private TLSDispatcherThread dispatcher;
    private DataOutputStream sout;
    /** key=circuit ID, value=circuit */
    private Map<Integer,Circuit> circuitMap = Collections.synchronizedMap(new HashMap<Integer,Circuit>());

    /**
     * creates the TLS connection and installs a dispatcher for incoming data.
     * 
     * @param server
     *            the server to connect to (e.g. a Tor Onion Router)
     * @param lowerNetLayer
     *            build TLS connection on this lower net layer
     * @param phk handler to check server certs
     *         
     * @see TLSDispatcherThread
     * @exception IOException
     * @exception SSLPeerUnverifiedException
     */
    TLSConnection(RouterImpl server, NetLayer lowerNetLayer, PrivateKeyHandler pkh) throws IOException,
            SSLPeerUnverifiedException, SSLException {
        if (server == null) {
            throw new IOException("TLSConnection: server variable is NULL");
        }
        this.router = server;

        // create new certificates and use them ad-hoc
        KeyManager kms[] = new KeyManager[1];
        
        // TODO: Leave out the PrivateKeyHandler, should be needed for 
        // server operation and hidden services only
        //kms[0] = pkh;

        // use the keys and certs from above to connect to Tor-network
        //try {
        TrustManager[] tms = { new TorX509TrustManager() };

        // new code:
        Map<String,Object> props = new HashMap<String,Object>();
        props.put(TLSNetLayer.ENABLES_CIPHER_SUITES, enabledSuitesStr);
        props.put(TLSNetLayer.TRUST_MANAGERS, tms);
        NetAddress remoteAddress = new TcpipNetAddress(server.getHostname(), server.getOrPort());
        NetAddress localAddress = null; 
        tls = lowerNetLayer.createNetSocket(props, localAddress, remoteAddress);
        
        // FIXME: check certificates received in TLS
        //        (note: not an important security bug, since it only affects hop2hop-encryption, real 
        //               data is encrypted anyway on top of TLS)

        /*
         * // for debugging purposes
         * javax.net.ssl.HandshakeCompletedListener hscl = new
         * javax.net.ssl.HandshakeCompletedListener() { public void
         * handshakeCompleted(HandshakeCompletedEvent e) { try {
         * log.info("Cipher: "+e.getCipherSuite());
         * java.security.cert.Certificate[] chain =
         * e.getLocalCertificates(); log.info("Send cert-chain of
         * length "+chain.length); for(int i=0;i<chain.length;++i)
         * log.info(" cert "+i+": "+chain[i].toString()); chain =
         * e.getPeerCertificates(); log.info("Received cert-chain
         * of length "+chain.length); for(int i=0;i<chain.length;++i)
         * log.info(" cert "+i+": "+chain[i].toString()); }
         * catch(Exception ex) {} } };
         * tls.addHandshakeCompletedListener(hscl);
         */

        // create object to write data to stream
        sout = new DataOutputStream(tls.getOutputStream());
        // start listening for incoming data
        this.dispatcher = new TLSDispatcherThread(this, new DataInputStream(tls.getInputStream()));
    }

    /**
     * converts a cell to bytes and transmitts it over the line. received data
     * is dispatched by the class TLSDispatcher
     * 
     * @param c
     *            the cell to send
     * @exception IOException
     * @see TLSDispatcherThread
     */
    synchronized void sendCell(Cell c) throws IOException {
        try {
            sout.write(c.toByteArray());
        } catch(IOException e) {
            // force to close the connection
            close(true);
            // rethrow error
            throw e;
        }
    }

    /**
     * returns a free circID and save that it points to "c", save it to "c",
     * too. Throws an exception, if no more free IDs are available, or the TLS
     * connection is marked as closed.<br>
     * FIXME: replace this code with something more beautiful
     * 
     * @param c
     *            the circuit that is going to be build through this
     *            TLS-Connection
     * @return an identifier for this new circuit - this must be set by the caller as id in the Circuit 
     * @exception TorException
     */
    synchronized int assignCircuitId(Circuit c) throws TorException {
        if (closed) {
            throw new TorException("TLSConnection.assignCircuitId(): Connection to "+router.getNickname()+" is closed for new circuits");
        }
        // find a free number (other than zero)
        int ID;
        int j = 0;
        do {
            if (++j > 1000) {
                throw new TorException("TLSConnection.assignCircuitId(): no more free IDs");
            }
            
            // Deprecated: 16 bit unsigned Integers with MSB set
            // ID = FirstNodeHandler.rnd.nextInt() & 0xffff | 0x8000;
            
            // XXX: Since the PrivateKeyHandler is gone, we don't need to consider 
            // the MSB as long as we are in client mode (see main-tor-spec.txt, Section 5.1) 
            ID = TLSConnectionAdmin.rnd.nextInt() & 0xffff; // & 0x7fff;
            
            if (circuitMap.containsKey(new Integer(ID))) {
                ID = 0;
            }
        } while (ID == 0);
        // memorize circuit
        circuitMap.put(new Integer(ID), c);
        return ID;
    }

    /**
     * marks as closed. closes if no more data or forced closed on real close:
     * kill dispatcher
     * 
     * @param force
     *            set to TRUE if established circuits shall be cut and
     *            terminated.
     */
    void close(boolean force) {
        log.fine("Closing TLS to " + router.getNickname());

        closed = true;
        // FIXME: a problem with (!force) is, that circuits, that are currently
        // still build up
        // are not killed. their build-up should be stopped
        // close circuits, if forced
        Collection<Circuit> circuits;
        synchronized(circuitMap) {
            circuits = new ArrayList<Circuit>(circuitMap.values());
        }
        for (Circuit circuit : circuits) {
            if (circuit.close(force)) {
                removeCircuit(circuit.getId());
            }        
        }
        
        log.fine("Fast exit while closing TLS to " + router.getNickname() +"?");
        if (!(force || circuitMap.isEmpty())) {
            log.fine("Fast exit while closing TLS to " + router.getNickname() +"!");
            return;
        }
        
        // kill dispatcher
        log.fine("Closing dispatcher of TLS to " + router.getNickname());
        dispatcher.close();

        // close TLS connection
        log.fine("Closing TLS connection to " + router.getNickname());
        try {
            sout.close();
            tls.close();
        } catch (IOException e) {
        }
        log.fine("Closing TLS to " + router.getNickname() + " done");
    }
    
    @Override
    public String toString() {
        return "TLS to " + router.getNickname();
    }

    ///////////////////////////////////////////////////////
    // getters and setters
    ///////////////////////////////////////////////////////
    

    public RouterImpl getRouter() {
        return router;
    }

    public void setRouter(RouterImpl router) {
        this.router = router;
    }

    public Collection<Circuit> getCircuits() {
        synchronized(circuitMap) {
            return new ArrayList<Circuit>(circuitMap.values());
        }
    }

    public Map<Integer, Circuit> getCircuitMap() {
        synchronized(circuitMap) {
            return new HashMap<Integer, Circuit>(circuitMap);
        }
    }
    
    public Circuit getCircuit(Integer circuitId) {
        synchronized(circuitMap) {
            return circuitMap.get(circuitId);
        }
    }
    
    /**
     * Remove 
     * @param circuitId
     * @return true=removed; false=not remove/did not exist
     */
    public boolean removeCircuit(Integer circuitId) {
        log.fine("remove circuit with circuitId="+circuitId+" from "+toString());

        // remove Circuit
        boolean result;
        boolean doClose;
        synchronized(circuitMap) {
            result = circuitMap.remove(circuitId)!=null;
            doClose = circuitMap.size()==0;
        }
        
        // last circuit of this TLSConnection removed: connection can be closed?
        if (doClose) {
            // yes
            log.fine("close TLSConnection from "+toString()+ " because last Circuit is removed");
            close(true);
        } else {
            // no
            synchronized(circuitMap) {
                log.fine("cannot close TLSConnection from "+toString()+ " because of additional circuits: "+ circuitMap);
            }
        }
        
        log.fine("remove circuit from "+toString() + " done with result="+result);
        return result;
    }
    
    public boolean isClosed() {
        return closed;
    }
}
