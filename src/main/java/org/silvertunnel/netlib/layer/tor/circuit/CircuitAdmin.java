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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.layer.tor.api.Fingerprint;
import org.silvertunnel.netlib.layer.tor.common.TCPStreamProperties;
import org.silvertunnel.netlib.layer.tor.common.TorConfig;
import org.silvertunnel.netlib.layer.tor.common.TorEventService;
import org.silvertunnel.netlib.layer.tor.directory.Directory;
import org.silvertunnel.netlib.layer.tor.directory.RouterImpl;
//import org.silvertunnel.netlib.layer.tor.directory.service.DirectoryService;
import org.silvertunnel.netlib.layer.tor.util.TorException;

/**
 * Handle circuits.
 * 
 * @author hapke
 */
public class CircuitAdmin {
    private static final Logger log = Logger.getLogger(CircuitAdmin.class.getName());

    // TODO test:
    /** key=host name, value=circuit to this host */
    static Map<String, Circuit[]> suitableCircuitsCache = Collections.synchronizedMap(new HashMap<String, Circuit[]>());


    /** fingerprint of currently used nodes in circuits as key, # of cirs - value */
    private static Map<Fingerprint,Integer> currentlyUsedNodes = Collections.synchronizedMap(new HashMap<Fingerprint,Integer>());

    private static Random rnd = new Random();
    
    static Circuit provideSuitableNewCircuit(TLSConnectionAdmin tlsConnectionAdmin, Directory dir, TCPStreamProperties sp, TorEventService torEventService) throws IOException {
        for (int retries = 0; retries < TorConfig.retriesConnect; ++retries) {
            try {
                return new Circuit(tlsConnectionAdmin, dir, sp, torEventService);
            } catch (InterruptedException e) {
                /* do nothing, continue trying */
            } catch (TorException e) {
                /* do nothing, continue trying */
            } catch (IOException e) {
                /* do nothing, continue trying */
            }
        }
        return null;
    }
    
    /**
     * Provide a circuit that can exclusively be used by the caller.
     * 
     * @param tlsConnectionAdmin
     * @param dir
     * @param sp
     * @param torEventService
     * @return
     * @throws IOException
     */
    public static Circuit provideSuitableExclusiceCircuit(TLSConnectionAdmin tlsConnectionAdmin, Directory dir, TCPStreamProperties sp, TorEventService torEventService) throws IOException {
        return provideSuitableNewCircuit(tlsConnectionAdmin, dir, sp, torEventService);
    }

    /**
     * used to return a number of circuits to a target. established a new circuit or uses an existing one
     *
     * @param sp gives some basic restrains
     * @param forHiddenService if set to true, use circuit that is unused and don't regard exit-policies
     */
    public static Circuit[] provideSuitableCircuits(
            TLSConnectionAdmin tlsConnectionAdmin, Directory dir, TCPStreamProperties sp, TorEventService torEventService, boolean forHiddenService)
    throws IOException {
        log.fine("TLSConnectionAdmin.provideSuitableCircuits: called for " + sp.getHostname());
        
        // TODO test: shortcut/cache
        Circuit[] cachedResults = suitableCircuitsCache.get(sp.getHostname());
        if (cachedResults != null) {
            // TODO return cachedResults;
        }

        // list all suiting circuits in a vector
        int numberOfExistingCircuits = 0;
        Vector<Circuit> allCircs = new Vector<Circuit>(10, 10);
        int rankingSum = 0;
        for (TLSConnection tls : tlsConnectionAdmin.getConnections()) {
            for (Circuit circuit : tls.getCircuits()) {
                try {
                    ++numberOfExistingCircuits;
                    if (circuit.isEstablished() && (!circuit.isClosed()) && DirectoryService.isCompatible(dir, circuit, sp, forHiddenService)) {
                        allCircs.add(circuit);
                        rankingSum += circuit.getRanking();
                    }
                } catch (TorException e) { /* do nothing, just try next circuit */ }
            }
        }
        // sort circuits (straight selection... O(n^2)) by
        // - whether they contained a stream to the specific address
        // - ranking (stochastically!)
        // - implicit: whether they haven't had a stream at all
        for (int i = 0; i < allCircs.size() - 1; ++i) {
            Circuit c1 = (Circuit) allCircs.get(i);
            int min = i;
            int minRanking = c1.getRanking();
            if (minRanking == 0) {
                minRanking = 1;
            }
            boolean minPointsToAddr = c1.getStreamHistory().contains(sp.getHostname());
            for (int j = i + 1; j < allCircs.size(); ++j) {
                Circuit thisCirc = (Circuit) allCircs.get(j);
                int thisRanking = thisCirc.getRanking();
                if (thisRanking == 0) {
                    thisRanking = 1;
                }
                boolean thisPointsToAddr = thisCirc.getStreamHistory().contains(sp.getHostname());
                float rankingQuota = thisRanking / minRanking;
                if ((thisPointsToAddr && !minPointsToAddr)|| (TLSConnectionAdmin.rnd.nextFloat() > Math.exp(-rankingQuota))) {
                    // sort stochastically
                    min = j;
                    minRanking = thisRanking;
                }
            }
            if (min > i) {
                Circuit temp = allCircs.set(i, allCircs.get(min));
                allCircs.set(min, temp);
            }
        }
        // return number of circuits suiting to number of stream-connect retries!
        int returnValues = sp.getConnectRetries();
        if (allCircs.size() < returnValues) {
            returnValues = allCircs.size();
        }
        if ((returnValues == 1) && (numberOfExistingCircuits < TorConfig.circuitsMaximumNumber)) {
            // spawn new circuit IN BACKGROUND, unless maximum number of
            // circuits reached
            log.fine("TLSConnectionAdmin.provideSuitableCircuits: spawning circuit to " + sp.getHostname() + " in background");
            Thread spawnInBackground = new NewCircuitThread(tlsConnectionAdmin, dir, sp, torEventService);
            spawnInBackground.setName("CuircuitAdmin.provideSuitableCircuits");
            spawnInBackground.start();
        } else if ((returnValues == 0) && (numberOfExistingCircuits < TorConfig.circuitsMaximumNumber)) {
            // spawn new circuit, unless maximum number of circuits reached
            log.fine("TLSConnectionAdmin.provideSuitableCircuits: spawning circuit to " + sp.getHostname());
            Circuit single = provideSuitableNewCircuit(tlsConnectionAdmin, dir, sp, torEventService);
            if (single != null) {
                returnValues = 1;
                allCircs.add(single);
            }
        }
        // copy values
        Circuit[] results = new Circuit[returnValues];
        for (int i = 0; i < returnValues; ++i) {
            results[i] = (Circuit) allCircs.get(i);
            if (log.isLoggable(Level.FINE)) {
                log.fine("TLSConnectionAdmin.provideSuitableCircuits: Choose Circuit ranking " + results[i].getRanking() + ":" + results[i].toString());
            }
        }

        // TODO gri test: shortcat/cache
        suitableCircuitsCache.put(sp.getHostname(), results);

        return results;
    }
    
    /**
     * returns a route through the network as specified in
     * 
     * @see TCPStreamProperties
     * 
     * @param sp tcp stream properties
     * @param propousedRoute   array of fingerprints of routers that were proposed by tcp stream properties
     * @param excludedServerNames selfexplained
     * @param route current route array
     * @param i index in array route up to which the route has to be built
     * @return a list of servers
     */
    synchronized private static RouterImpl[] createNewRoute(Directory directory, TCPStreamProperties sp, Fingerprint[] proposedRoute, HashSet<Fingerprint> excludedServerFingerprints, RouterImpl[] route, int i, int maxIterations)
         throws TorException{

        float p = sp.getRankingInfluenceIndex();
        HashSet<Fingerprint> previousExcludedServerFingerprints = new HashSet<Fingerprint>();

        Map<Fingerprint,RouterImpl> validRoutersByFingerprint = directory.getValidRoutersByFingerprint();
        for (RouterImpl r : validRoutersByFingerprint.values()) {
            Integer allowedCircuitsWithNode = CircuitAdmin.currentlyUsedNodes.get(r.getFingerprint());
            // exit server must be trusted
            if ((allowedCircuitsWithNode != null) && (allowedCircuitsWithNode.intValue() > TorConfig.allowModeMultipleCircuits)) {
                excludedServerFingerprints.add(r.getFingerprint());
            }
        }

        if ((proposedRoute != null) && (i < proposedRoute.length) && (proposedRoute[i] != null)) {
            // choose proposed server
            route[i] = (RouterImpl) validRoutersByFingerprint.get(proposedRoute[i]);
            if (route[i] == null) {
                throw new TorException("couldn't find server " + proposedRoute[i] + " for position " + i);
            }
        } else {

            if (i == route.length - 1) { 
                // the last router has to accept exit policy

                // determine suitable servers
                HashSet<Fingerprint> suitableServerFingerprints = new HashSet<Fingerprint>(); 
                for (RouterImpl r : validRoutersByFingerprint.values()) {
                    // exit server must be trusted
                    if (r.exitPolicyAccepts(sp.getAddr(), sp.getPort()) && (sp.isUntrustedExitAllowed() || r.isDirv2Exit())) {
                        suitableServerFingerprints.add(r.getFingerprint());
                    }
                }

                HashSet<Fingerprint> x = new HashSet<Fingerprint>(validRoutersByFingerprint.keySet());
                x.removeAll(suitableServerFingerprints);
                x.addAll(excludedServerFingerprints);
                // now select one of them

                route[i] = directory.selectRandomNode(validRoutersByFingerprint, x, p);

            } else if ((i == 0) && (!sp.isNonGuardEntryAllowed())) {
                // entry node must be guard

                // determine suitable servers
                HashSet<Fingerprint> suitableServerFingerprints = new HashSet<Fingerprint>(); 
                for (RouterImpl r : validRoutersByFingerprint.values()) {
                    // entry server must be guard
                    if (r.isDirv2Guard()) {
                        suitableServerFingerprints.add(r.getFingerprint());
                    }
                }

                HashSet<Fingerprint> x = new HashSet<Fingerprint>(validRoutersByFingerprint.keySet());
                x.removeAll(suitableServerFingerprints);
                x.addAll(excludedServerFingerprints);
                // now select one of them
                route[i] = directory.selectRandomNode(validRoutersByFingerprint, x, p);

            } else {
                route[i] = directory.selectRandomNode(validRoutersByFingerprint, excludedServerFingerprints, p);
            }

            if (route[i] == null) {
                return null;
            }
            previousExcludedServerFingerprints.addAll(excludedServerFingerprints);
            excludedServerFingerprints.addAll(directory.excludeRelatedNodes(route[i]));

            int numberOfNodeOccurances;
            Integer allowedCircuitsWithNode = CircuitAdmin.currentlyUsedNodes.get(route[i].getNickname());
            if (allowedCircuitsWithNode != null) {
                numberOfNodeOccurances = allowedCircuitsWithNode.intValue() + 1;
            } else {
                numberOfNodeOccurances = 0;
            }
            CircuitAdmin.currentlyUsedNodes.put(route[i].getFingerprint(), numberOfNodeOccurances);
        }

        if (i > 0) {
            RouterImpl[] aRoute = createNewRoute(directory, sp, proposedRoute, excludedServerFingerprints, route, i - 1, -1);
            if (aRoute == null) {

                previousExcludedServerFingerprints.add(route[i - 1].getFingerprint());
                if (maxIterations > -1) {
                    maxIterations = Math.min(maxIterations, Directory.RETRIES_ON_RECURSIVE_ROUTE_BUILD) - 1;
                } else {
                    maxIterations = Directory.RETRIES_ON_RECURSIVE_ROUTE_BUILD - 1;
                }
                if (maxIterations < 0) {
                    return null;
                }
                route = createNewRoute(directory, sp, proposedRoute,
                        previousExcludedServerFingerprints, route, i, maxIterations);

            } else {
                route = aRoute;
            }
        }

        return route;
    }

    /**
     * returns a route through the network as specified in
     * 
     * @see TCPStreamProperties
     * 
     * @param sp
     *            tcp stream properties
     * @return a list of servers
     */
    public static RouterImpl[] createNewRoute(Directory directory, TCPStreamProperties sp) throws TorException {
        // are servers available?
        if (directory.getValidRoutersByFingerprint().size() < 1) {
            throw new TorException("directory is empty");
        }

        // use length of route proposed by TCPStreamProperties
        int minRouteLength = sp.getMinRouteLength();
        int len;

        // random value between min and max route length
        len = minRouteLength + rnd.nextInt(sp.getMaxRouteLength() - minRouteLength + 1);

        // choose random servers to form route
        RouterImpl[] route = new RouterImpl[len];

        HashSet<Fingerprint> excludedServerFingerprints = new HashSet<Fingerprint>();
        // take care, that none of the specified proposed servers is selected
        // before in route
        Fingerprint[] proposedRoute = sp.getProposedRouteFingerprints();
        if (proposedRoute != null) {
            for (int j = 0; j < proposedRoute.length; ++j) {
                if (proposedRoute[j] != null) {
                    RouterImpl s = (RouterImpl) directory.getValidRoutersByFingerprint().get(proposedRoute[j]);
                    if (s != null) {
                        excludedServerFingerprints.addAll(directory.excludeRelatedNodes(s));
                    }
                }
            }
        }
        RouterImpl[] result = createNewRoute(directory, sp, proposedRoute, excludedServerFingerprints, route, len-1, -1);

        // the end
        if (result==null) {
            log.warning("result new route is null");
        } else {
            if (log.isLoggable(Level.INFO)) {
                StringBuffer sb = new StringBuffer();
                for (RouterImpl server : result) {
                    sb.append("server(or="+server.getHostname()+":"+server.getOrPort()+"("+server.getNickname()+"), fp="+server.getFingerprint()+") ");
                }
                log.info("result new route: "+sb.toString());
            }
        }
        return result;
    }

    /**
     * restores circuit from the failed node route[failedNode]
     * 
     * @param sp
     *            tcp stream properties
     * @param route
     *            existing route
     * @param failedNode
     *            index of node in route, that failed
     * @return a route
     */
    public static RouterImpl[] restoreCircuit(Directory directory, TCPStreamProperties sp, RouterImpl[] route,
            int failedNode) throws TorException {

        // used to build the custom route up to the failed node
        Fingerprint[] customRoute = new Fingerprint[route.length];

        // if TCPStreamProperties are NA, create a new one
        if (sp == null) {
            sp = new TCPStreamProperties();
        }

        // customize sp, so that createNewRoute could be used to do the job
        //   make sure we build circuit of the same length
        sp.setMinRouteLength(route.length);
        //   it used to be
        sp.setMaxRouteLength(route.length); // 
        // make sure now to select with higher prob. reliable servers
        sp.setRankingInfluenceIndex(1.0f); 

        // decreasing ranking of the failed one
        route[failedNode].punishRanking();

        // reuse hosts that are required due to TCPStreamProperties
        if (sp.getRouteFingerprints() != null) {
            for (int i = 0; (i < sp.getRouteFingerprints().length) && (i < customRoute.length); ++i) {
                customRoute[i] = sp.getRouteFingerprints()[i];
            }
        }
        // reuse hosts that were reported to be working
        for (int i = 0; i < failedNode; ++i) {
            customRoute[i] = route[i].getFingerprint();
        }

        sp.setCustomRoute(customRoute);

        try {
            route = createNewRoute(directory, sp);

        } catch (TorException te) {
            log.warning("Directory.restoreCircuit: failed");
        }

        return route;
    }
    
    public static Integer getCurrentlyUsedNode(Fingerprint fingerprint) {
        return currentlyUsedNodes.get(fingerprint);
    }
    
    public static void putCurrentlyUsedNodeNumber(Fingerprint fingerprint, Integer value) {
        currentlyUsedNodes.put(fingerprint, value);
    }
    
    /**
     * Remove the current history.
     * Close all circuits that were already be used.
     */
    public static void clear(TLSConnectionAdmin tlsConnectionAdmin) {
        suitableCircuitsCache.clear();
        
        // close all circuits that were already be used.
        for (TLSConnection tls : tlsConnectionAdmin.getConnections()) {
            for (Circuit circuit : tls.getCircuits()) {
                if (circuit.isEstablished() || circuit.getStreamHistory().size()>0) {
                    circuit.close(true);
                }
            }
        }
   }
}
