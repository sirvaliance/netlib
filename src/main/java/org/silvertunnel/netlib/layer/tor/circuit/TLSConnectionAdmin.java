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

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.logging.Logger;

import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.layer.tor.api.Fingerprint;
import org.silvertunnel.netlib.layer.tor.directory.RouterImpl;
import org.silvertunnel.netlib.layer.tor.util.PrivateKeyHandler;
import org.silvertunnel.netlib.layer.tor.util.TorException;


/**
 * maintains the list of active TLS-connections to Tor nodes
 * (direct connections to neighbor nodes).
 * 
 * Hint: previous class name = FirstNodeHandler
 * 
 * @author Lexi Pimenidis
 * @author Andriy Panchenko
 * @author hapke
 */
public class TLSConnectionAdmin {
    private static final Logger log = Logger.getLogger(TLSConnectionAdmin.class.getName());
    
    static Random rnd = new Random();

    /** key=fingerprint, value=connection to this router */
    private Map<Fingerprint,WeakReference<TLSConnection>> connectionMap = Collections.synchronizedMap(new HashMap<Fingerprint,WeakReference<TLSConnection>>());
    
    /** key=fingerprint, value=connection to this router;
     * contains all connections of all TLSConnectionAdmin instances,
     * used by some test cases
     */
    private static Map<Fingerprint,WeakReference<TLSConnection>> connectionMapAll = Collections.synchronizedMap(new HashMap<Fingerprint,WeakReference<TLSConnection>>());
  
    
    /** lower layer network layer, e.g. TLS over TCP/IP to connect to TOR onion routers */
    private NetLayer lowerTlsConnectionNetLayer;
    private PrivateKeyHandler privateKeyHandler;
    
    /**
     * initialize Handler of TLSConnections
     */
    public TLSConnectionAdmin(NetLayer lowerTlsConnectionNetLayer, PrivateKeyHandler privateKeyHandler) throws IOException {
        this.lowerTlsConnectionNetLayer = lowerTlsConnectionNetLayer;
        this.privateKeyHandler = privateKeyHandler;
    }

    /**
     * return a pointer to a direct TLS-connection to a certain node. if there is
     * none, it is created and returned.
     * 
     * @param router
     *            the node to connect to
     * @return the TLS connection
     */
    TLSConnection getConnection(RouterImpl router) throws IOException, TorException {
        if (router == null) {
            throw new TorException("TLSConnectionAdmin: server is NULL");
        }
        // check if TLS-connections to node established
        WeakReference<TLSConnection> weakConn = connectionMap.get(router.getFingerprint());
        TLSConnection conn = null;
        if (weakConn!=null) {
            conn = weakConn.get();
        }
        if (conn==null) {
            // not in cache: build new TLS connection
            log.fine("TLSConnectionAdmin: TLS connection to " + router.getNickname());
            conn = new TLSConnection(router, lowerTlsConnectionNetLayer, privateKeyHandler);
            weakConn = new WeakReference<TLSConnection>(conn);
            connectionMap.put(router.getFingerprint(), weakConn);
            connectionMapAll.put(router.getFingerprint(), weakConn);
        }
        return conn;
    }
 
    /**
     * Remove TLSConnection if it was closed.
     * 
     * @param conn
     */
    public void removeConnection(TLSConnection conn) {
        connectionMap.remove(conn.getRouter().getFingerprint());
    }
    
    /**
     * Closes all TLS connections.
     * 
     * This method is used by some test cases
     * and it it not intended to make this method public.
     */
    static void closeAllTlsConnections() {
        synchronized(connectionMapAll) {
            for (WeakReference<TLSConnection> w : connectionMapAll.values()) {
                TLSConnection t = w.get();
                if (t!=null) {
                    t.close(true);
                }
            }
            connectionMapAll.clear();
        }
    }

    /**
     * closes all TLS connections
     * 
     * @param force
     *            set to false, if circuits shall be terminated gracefully
     */
    public void close(boolean force) {
        synchronized(connectionMap) {
            for (WeakReference<TLSConnection> w : connectionMap.values()) {
                TLSConnection t = w.get();
                if (t!=null) {
                    t.close(force);
                }
            }
            connectionMap.clear();
        }
    }

    public Collection<TLSConnection> getConnections() {
        // create new Collection to avoid concurrent modifications,
        // use the iteration to remove weak references that lost it object
        Collection<Fingerprint> entriesToRemove = new ArrayList<Fingerprint>(connectionMap.size());
        Collection<TLSConnection> result = new ArrayList<TLSConnection>(connectionMap.size());
        synchronized(connectionMap) {
            for (Fingerprint f : connectionMap.keySet()) {
                WeakReference<TLSConnection> w = connectionMap.get(f);
                if (w!=null) {
                    TLSConnection t = w.get();
                    if (t!=null) {
                        // valid TLSConnection found
                        result.add(t);
                    } else {
                        // entry with lost reference found
                        entriesToRemove.add(f);
                    }
                }
            }
            // cleanup (part 1)
            for (Fingerprint f : entriesToRemove) {
                connectionMap.remove(f);
            }
        }
        synchronized(connectionMapAll) {
            // cleanup (part 2)
            for (Fingerprint f : entriesToRemove) {
                connectionMapAll.remove(f);
            }
        }
        return result;
    }
}

