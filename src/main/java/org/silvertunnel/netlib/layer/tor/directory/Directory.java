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

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.util.IpNetAddress;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.control.ControlNetLayer;
import org.silvertunnel.netlib.layer.control.ControlParameters;
import org.silvertunnel.netlib.layer.tor.api.Fingerprint;
import org.silvertunnel.netlib.layer.tor.api.TorNetLayerStatus;
import org.silvertunnel.netlib.layer.tor.common.TCPStreamProperties;
import org.silvertunnel.netlib.layer.tor.common.TorConfig;
import org.silvertunnel.netlib.layer.tor.util.NetLayerStatusAdmin;
import org.silvertunnel.netlib.layer.tor.util.Parsing;
import org.silvertunnel.netlib.layer.tor.util.TorException;
import org.silvertunnel.netlib.tool.SimpleHttpClient;
import org.silvertunnel.netlib.util.StringStorage;


/**
 * This class maintains a list of the currently known Tor routers. It has
 * the capability to update stats and find routes that fit to certain criteria.
 * 
 * @author Lexi Pimenidis
 * @author Tobias Koelsch
 * @author Andriy Panchenko
 * @author Michael Koellejan
 * @author Johannes Renner
 * @author hapke
 */
public class Directory {
    private static final Logger log = Logger.getLogger(Directory.class.getName());

    /**
     *  Number of retries to find a route on one recursive stap before falling
     *  back and changing previous node
     */
    public static final int RETRIES_ON_RECURSIVE_ROUTE_BUILD = 10; 
    /** time intervals to poll descriptor fetchers for result in milliseconds */
    static final int FETCH_THREAD_QUERY_TIME_MS = 2000;

    /** key to locally cache the authority key certificates */ 
    private static final String STORAGEKEY_AUTHORITY_KEY_CERTIFICATES_TXT = "authority-key-certificates.txt";
    /** key to locally cache the consensus */ 
    private static final String STORAGEKEY_DIRECTORY_CACHED_CONSENSUS_TXT = "directory-cached-consensus.txt";
    /** key to locally cache the router descriptors */ 
    private static final String STORAGEKEY_DIRECTORY_CACHED_ROUTER_DESCRIPTORS_TXT = "directory-cached-router-descriptors.txt";

    private TorConfig torConfig;
    /** local cache */
    private StringStorage stringStorage;
    /** lower layer network layer, e.g. TCP/IP to connect to directory servers */
    public NetLayer lowerDirConnectionNetLayer;
    /** collection of all valid Tor server (all routers that are valid or were valid in the past) */
    private Map<Fingerprint,RouterImpl> allFingerprintsRouters = Collections.synchronizedMap(new HashMap<Fingerprint,RouterImpl>());
    /** the last valid consensus */
    private DirectoryConsensus directoryConsensus;
    /** cache: number of running routers in the consensus */
    private int numOfRunningRoutersInDirectoryConsensus = 0;
    /**
     * cache of a combination of fingerprintsRouters+directoryConsensus: valid routers + status
     * 
     * key=identity key
     */
    private Map<Fingerprint,RouterImpl> validRoutersByFingerprint = new HashMap<Fingerprint,RouterImpl>();
    /**
     * Map that has class C address as key, and a HashSet with fingerprints
     * of Nodes that have IP-Address of that class
     */
    private Map<String, HashSet<Fingerprint>> addressNeighbours;
    /**
     * HashMap where keys are CountryCodes, and values are HashSets with fingerprints
     * of Nodes having an IP-address in the specific country
     */
    private Map<String, HashSet<Fingerprint>> countryNeighbours;
    /** HashSet excluded by config nodes */
    private HashSet<Fingerprint> excludedNodesByConfig;
    private Random rnd;
    
    private volatile boolean updateRunning = false;
    private int updateCounter = 0;

    private AuthorityKeyCertificates authorityKeyCertificates;
    
    private NetLayerStatusAdmin statusAdmin;

    private static final long ONE_DAY_IN_MS = 1L*24L*60L*60L*1000L;
    
    private static final Pattern IPCLASSC_PATTERN = Parsing.compileRegexPattern("(.*)\\.");
    
    /**
     * Initialize directory to prepare later network operations.
     */
    public Directory(TorConfig torConfig, StringStorage stringStorage, NetLayer lowerDirConnectionNetLayer, KeyPair dirServerKeys, NetLayerStatusAdmin statusAdmin) {
        // initialization from network
        // is done from background mgmt .. but should be done here a first time
        // NOTE FROM LEXI: refreshListOfServers MUST NOT be called from here, 
        // but instead MUST be called from background mgmt
        //refreshListOfServers();
 
        // save parameters
        this.torConfig = torConfig;
        this.stringStorage = stringStorage;
        this.lowerDirConnectionNetLayer = lowerDirConnectionNetLayer;
        this.statusAdmin = statusAdmin;

        // configure special timeout parameters for download of directory information
        ControlParameters cp = ControlParameters.createTypicalFileTransferParameters();
        cp.setConnectTimeoutMillis(TorConfig.DIR_CONNECT_TIMEOUT_MILLIS);
        cp.setOverallTimeoutMillis(TorConfig.DIR_OVERALL_TIMEOUT_MILLIS);
        cp.setInputMaxBytes(TorConfig.DIR_MAX_FILETRANSFER_BYTES);
        cp.setThroughputTimeframeMinBytes(TorConfig.DIR_THROUGPUT_TIMEFRAME_MIN_BYTES);
        cp.setThroughputTimeframeMillis(TorConfig.DIR_THROUGPUT_TIMEFRAME_MILLIS);
        this.lowerDirConnectionNetLayer = new ControlNetLayer(lowerDirConnectionNetLayer, cp);
        
        // rest
        addressNeighbours = new HashMap<String, HashSet<Fingerprint>>();
        countryNeighbours = new HashMap<String, HashSet<Fingerprint>>();
        rnd = new Random();
        excludedNodesByConfig = new HashSet<Fingerprint>();
        Collection<byte[]> avoidedNodeFingerprints = TorConfig.avoidedNodeFingerprints;
        for (byte[] fingerprint : avoidedNodeFingerprints) {
            excludedNodesByConfig.add(new FingerprintImpl(fingerprint));
        }
    }


    /**
     * Add s to addressNeighbours and countryNeighbours.
     * 
     * @param r
     */
    private void addToNeighbours(RouterImpl r){
        HashSet<Fingerprint> neighbours;
        String ipClassCString = Parsing.parseStringByRE(r.getAddress().getHostAddress(), IPCLASSC_PATTERN, "");
        
        // add it to the addressNeighbours
        neighbours =  addressNeighbours.get(ipClassCString);
        if (neighbours==null) {
            // first entry for this ipClassCString
            neighbours = new HashSet<Fingerprint>();
            addressNeighbours.put(ipClassCString, neighbours);
        }
        neighbours.add(r.getFingerprint());

        // add it to the country neighbours
        neighbours =  countryNeighbours.get(r.getCountryCode());
        if (neighbours==null) {
            // first entry for this s.countryCode
            neighbours = new HashSet<Fingerprint>();
            countryNeighbours.put(r.getCountryCode(), neighbours);
        }
        neighbours.add(r.getFingerprint());
    }

    /**
     * 
     * @return true if directory was loaded and enough routers are available
     */
    public boolean isDirectoryReady() {
        if (numOfRunningRoutersInDirectoryConsensus > 0) {
            long minDescriptors = Math.max(Math.round(TorConfig.minDescriptorsPercentage*numOfRunningRoutersInDirectoryConsensus), TorConfig.minDescriptors);
            if (validRoutersByFingerprint.size() > Math.max(minDescriptors, TorConfig.routeMinLength)) {
                // ready
                return true;
            } else {
                // not yet ready
                return false;
            }
        } else {
            // consensus or router details not yet loaded
            return false;
        }
    }

    /**
     * @return all routers that can be used; cached dirs a preferred if they are known
     */
    private Collection<RouterImpl> getDirRouters() {
        // filter
        Collection<RouterImpl> cacheDirs;
        Collection<RouterImpl> authorityDirs;
        synchronized(allFingerprintsRouters) {
            cacheDirs = new ArrayList<RouterImpl>(allFingerprintsRouters.size());
            authorityDirs = new ArrayList<RouterImpl>();
            for (RouterImpl r : allFingerprintsRouters.values()) {
                if (r.isValid()) {
                    // is this a authority dir?
                    if (r.isDirv2Authority()) {
                        authorityDirs.add(r);
                        
                       // is this a dir?    
                    } else if (r.isDirv2V2dir()) {
                        cacheDirs.add(r);
                    }
                }
            }
        }
        
        // prefer non-authorities
        final int MIN_NUM_OF_DIRS = 5;
        final int MIN_NUM_OF_CACHE_DIRS = MIN_NUM_OF_DIRS;
        if (cacheDirs.size()>=MIN_NUM_OF_CACHE_DIRS) {
            return cacheDirs;
        }
        
        // try authorities
        if (authorityDirs.size()+cacheDirs.size()>=MIN_NUM_OF_DIRS) {
            Collection<RouterImpl> result = cacheDirs;
            result.addAll(authorityDirs);
            return result;
        }
        
        // try predefined/hard-coded authorities
        return AuthorityServers.getAuthorityRouters();
    }

    /**
     * Poll some known servers, is triggered by TorBackgroundMgmt
     * and directly after starting.<br>
     * TODO : Test if things do not break if suddenly servers disappear from the directory that are currently being used<br>
     * TODO : Test if servers DO disappear from the directory
     *
     * @return 0 = no update, 1 = v1 update, 2 = v2 update, 3 = v3 update
     */
    public int refreshListOfServers() {
      // Check if there's already an update running
      synchronized(this) {
          if (updateRunning) {
              log.info("Directory.refreshListOfServers: update already running...");
              return 0;
          }
          updateRunning = true;
      
         try {
              updateNetworkStatusNew();
              // TODO old: updateNetworkStatusV3(v3Servers);
              // Finish, if some nodes were found
              if (isDirectoryReady()) {
                updateRunning = false;
                return 3;
              }
              return 0;
            } catch(Exception e) {
                log.log(Level.WARNING, "Directory.refreshListOfServers", e);
                return 0;
         
          } finally {
              updateRunning = false;
          }
      }
    }

    /**
     * Get a V3 network-status consensus, parse it and initiate downloads of missing descriptors
     * 
     * @param v3Servers
     * @throws TorException
     */
    private synchronized void updateNetworkStatusNew() throws TorException {
        ++updateCounter;

        //
        // handle consensus
        //
        statusAdmin.updateStatus(TorNetLayerStatus.CONSENSUS_LOADING);

        // pre-check
        Date now = new Date();
        if (directoryConsensus!=null && !directoryConsensus.needsToBeRefreshed(now)) {
            log.info("no consensus update necessary ...");
        } else {
            AuthorityKeyCertificates authorityKeyCertificates = getAuthorityKeyCertificates();

            //
            // first initialization attempt: use cached consensus
            //
            log.info("consensus first initialization attempt: try to use document from local cache ...");
            DirectoryConsensus newDirectoryConsensus = null;
            if (directoryConsensus==null || directoryConsensus.getFingerprintsNetworkStatusDescriptors().size()==0) {
                // first initialization: try to load consensus from cache
                String newDirectoryConsensusStr = stringStorage.get(STORAGEKEY_DIRECTORY_CACHED_CONSENSUS_TXT);
                final int MIN_LENGTH_OF_CONSENSUS_STR = 100;
                if (newDirectoryConsensusStr!=null && newDirectoryConsensusStr.length()>MIN_LENGTH_OF_CONSENSUS_STR) {
                    try {
                        newDirectoryConsensus = new DirectoryConsensus(newDirectoryConsensusStr, authorityKeyCertificates, now);
                        if (newDirectoryConsensus==null || !newDirectoryConsensus.isValid(now)) {
                            // cache result was not acceptable
                            newDirectoryConsensus = null;
                            log.info("consensus from local cache (is too small and) could not be used");
                        } else {
                            log.info("use consensus from local cache");
                        }
                    } catch (TorException e) {
                        newDirectoryConsensus = null;
                        log.info("consensus from local cache is not valid (e.g. too old) and could not be used");
                    } catch (Exception e) {
                        newDirectoryConsensus = null;
                        log.info("error while loading consensus from local cache: "+e);
                    }
                } else {
                    newDirectoryConsensus = null;
                    log.info("consensus from local cache (is null or invalid and) could not be used");
                }
            }

            //
            // ordinary update: load consensus from Tor network
            //
            log.info("load consensus from Tor network");
            if (newDirectoryConsensus==null) {
                 // all v3 directory servers
                List<RouterImpl> dirRouters = new ArrayList<RouterImpl>(getDirRouters());
                
                // Choose one randomly
                while (dirRouters.size()>0) {
                    int index = rnd.nextInt(dirRouters.size());
                    RouterImpl dirRouter = dirRouters.get(index);
                    log.info("Directory.updateNetworkStatusNew: Randomly chosen dirRouter to fetch consensus document: "+dirRouter.getFingerprint() +" ("+dirRouter.getNickname()+")");
                    try {
                        // download network status from server
                        final String path = "/tor/status-vote/current/consensus";
                        String newDirectoryConsensusStr = SimpleHttpClient.getInstance().get(lowerDirConnectionNetLayer, dirRouter.getDirAddress(), path);
                        
                        // Parse the document
                        newDirectoryConsensus = new DirectoryConsensus(newDirectoryConsensusStr, authorityKeyCertificates, now);
                        if (!newDirectoryConsensus.needsToBeRefreshed(now)) {
                            // result is acceptable
                            log.info("use new consensus");
                            // save the directoryConsensus for later Tor-startups
                            stringStorage.put(STORAGEKEY_DIRECTORY_CACHED_CONSENSUS_TXT, newDirectoryConsensusStr);
                            break;
                        }
                        newDirectoryConsensus = null;
                    } catch (Exception e) {
                      log.log(Level.WARNING, "Directory.updateNetworkStatusNew Exception", e);
                      dirRouters.remove(index);
                      newDirectoryConsensus = null;
                    }
                }
            }  

            // finalize consensus update
            if (newDirectoryConsensus!=null) {
                directoryConsensus = newDirectoryConsensus;
            } 
        }
        // final check whether a new or at least an old consensus is available
        if (directoryConsensus==null) {
            log.severe("no old or new directory consensus available");
            return;
        }

        
        //
        // update router descriptors
        //
        statusAdmin.updateStatus(TorNetLayerStatus.ROUTER_DESCRIPTORS_LOADING);
        if (directoryConsensus!=null) {
            // update router details
            fetchDescriptors(allFingerprintsRouters, directoryConsensus);
        
            // merge directoryConsensus&fingerprintsRouters -> validRoutersBy[Fingerprint|Name]
            Map<Fingerprint,RouterImpl> newValidRoutersByfingerprint = new HashMap<Fingerprint,RouterImpl>();
            int newNumOfRunningRoutersInDirectoryConsensus = 0;
            for (RouterStatusDescription networkStatusDescription : directoryConsensus.getFingerprintsNetworkStatusDescriptors().values()) {
                // one server of consensus
                Fingerprint fingerprint = networkStatusDescription.getFingerprint();
                RouterImpl r = allFingerprintsRouters.get(fingerprint);
                if (r!=null && r.isValid()) {
                    // valid server with description
                    r.updateServerStatus(networkStatusDescription.getFlags());
                    newValidRoutersByfingerprint.put(fingerprint, r);
                }
                if (networkStatusDescription.getFlags().contains("Running")) {
                    newNumOfRunningRoutersInDirectoryConsensus++;
                }
            }
            validRoutersByFingerprint = newValidRoutersByfingerprint;
            numOfRunningRoutersInDirectoryConsensus=newNumOfRunningRoutersInDirectoryConsensus;
        
            log.info("updated torServers, new size="+validRoutersByFingerprint.size());
            
            // write server descriptors to local cache
            StringBuffer allDescriptors = new StringBuffer();
            for (RouterImpl r : validRoutersByFingerprint.values()) {
                allDescriptors.append(r.getRouterDescriptor()).append("\n");
            }
            stringStorage.put(STORAGEKEY_DIRECTORY_CACHED_ROUTER_DESCRIPTORS_TXT, allDescriptors.toString());
            log.info("wrote router descriptors to local cache");
        }
    }

    private AuthorityKeyCertificates getAuthorityKeyCertificates() {
        // get now+1 day
        Date now = new Date();
        Date minValidUntil = new Date(now.getTime()+ONE_DAY_IN_MS);
        
        if (authorityKeyCertificates==null) {
            // loading is needed - try to load authority key certificates from cache first
            log.info("getAuthorityKeyCertificates(): try to load from local cache ...");
            String authorityKeyCertificatesStr = stringStorage.get(STORAGEKEY_AUTHORITY_KEY_CERTIFICATES_TXT);
            final int MIN_LENGTH_OF_AUTHORITY_KEY_CERTS_STR = 100;
            if (authorityKeyCertificatesStr!=null && authorityKeyCertificatesStr.length()>MIN_LENGTH_OF_AUTHORITY_KEY_CERTS_STR) {
                // parse loaded result
                try {
                    AuthorityKeyCertificates newAuthorityKeyCertificates = new AuthorityKeyCertificates(authorityKeyCertificatesStr, minValidUntil);
                    
                    // no exception thrown: certificates are OK
                    if (newAuthorityKeyCertificates.isValid(minValidUntil)) {
                        log.info("getAuthorityKeyCertificates(): successfully loaded from local cache");
                        authorityKeyCertificates = newAuthorityKeyCertificates;
                        return authorityKeyCertificates;
                    } else {
                        // do not use outdated or invalid certificates from local cache 
                        log.info("getAuthorityKeyCertificates(): loaded from local cache - but not valid: try (re)load from remote site now");
                    }

                } catch (TorException e) {
                    log.log(Level.WARNING, "getAuthorityKeyCertificates(): could not parse from local cache: try (re)load from remote site now", e);
                }
            } else {
                log.info("getAuthorityKeyCertificates(): no data in cache: try (re)load from remote site now");
            }
        }
               
        if (authorityKeyCertificates==null || !authorityKeyCertificates.isValid(minValidUntil)) {
            // (re)load is needed
            log.info("getAuthorityKeyCertificates(): load and parse authorityKeyCertificates...");
            List<String> authServerIpAndPorts = new ArrayList<String>(AuthorityServers.getAuthorityIpAndPorts());
            Collections.shuffle(authServerIpAndPorts);
            String httpResponse = null; 
            for (String authServerIpAndPort : authServerIpAndPorts) {
                // download authority key certificates
                try {
                    TcpipNetAddress hostAndPort = new TcpipNetAddress(authServerIpAndPort);
                    String path = "/tor/keys/all";
                    httpResponse = SimpleHttpClient.getInstance().get(lowerDirConnectionNetLayer, hostAndPort, path);

                    // parse loaded result
                    AuthorityKeyCertificates newAuthorityKeyCertificates = new AuthorityKeyCertificates(httpResponse, minValidUntil);

                    // no exception thrown: certificates are OK
                    if (newAuthorityKeyCertificates.isValid(minValidUntil)) {
                        log.info("getAuthorityKeyCertificates(): successfully loaded from " + authServerIpAndPort);
                        // save in cache
                        stringStorage.put(STORAGEKEY_AUTHORITY_KEY_CERTIFICATES_TXT, httpResponse);
                        // use as result
                        authorityKeyCertificates = newAuthorityKeyCertificates;
                        return authorityKeyCertificates;
                    } else {
                        log.info("getAuthorityKeyCertificates(): loaded from " + authServerIpAndPort + " - but not valid: try next");
                    }
                } catch (TorException e) {
                    log.log(Level.WARNING, "getAuthorityKeyCertificates(): could not parse from "+ authServerIpAndPort+ " result="+httpResponse+", try next", e);
                } catch(Exception e) {
                    if (log.isLoggable(Level.FINE)) {
                        log.log(Level.FINE, "getAuthorityKeyCertificates(): error while loading from "+ authServerIpAndPort+", try next", e);
                    } else {
                        log.info("getAuthorityKeyCertificates(): error while loading from "+ authServerIpAndPort+", try next ("+e+")");
                    }
                }
            }
            log.severe("getAuthorityKeyCertificates(): could NOT load and parse authorityKeyCertificates");
            // use outdated certificates if no newer could be retrieved
        }

        return authorityKeyCertificates;
    }


    /**
     * Trigger download of missing descriptors from directory caches
     * 
     * @param fingerprintsRouters    will be modified/updated inside this method
     * @param directoryConsensus     will be read
     */
    private void fetchDescriptors(Map<Fingerprint,RouterImpl> fingerprintsRouters, DirectoryConsensus directoryConsensus) 
       throws TorException {
        Set<Fingerprint> fingerprintsOfRoutersToLoad = new HashSet<Fingerprint>();
        
        for (RouterStatusDescription networkStatusDescription : directoryConsensus.getFingerprintsNetworkStatusDescriptors().values()) {
            // check one router of the consensus
            RouterImpl r = fingerprintsRouters.get(networkStatusDescription.getFingerprint());
            if (r==null || !r.isValid()) {
                // router description not yet contained or too old -> load it
                fingerprintsOfRoutersToLoad.add(networkStatusDescription.getFingerprint());
            }
        }
        
        //
        // load missing descriptors
        //
        final int ALL_DESCRIPTORS_STR_MIN_LEN = 1000;
       
        // try to load from local cache
           String allDescriptors;
        if (fingerprintsRouters.size()==0) {
            // try to load from local cache
            allDescriptors = stringStorage.get(STORAGEKEY_DIRECTORY_CACHED_ROUTER_DESCRIPTORS_TXT);
        
            // split into single server descriptors
            if (allDescriptors!=null && allDescriptors.length()>=ALL_DESCRIPTORS_STR_MIN_LEN) {
                Map<Fingerprint,RouterImpl> parsedServers = RouterImpl.parseRouterDescriptors(torConfig, allDescriptors);
                Set<Fingerprint> fingerprintsOfRoutersToLoadCopy = new HashSet<Fingerprint>(fingerprintsOfRoutersToLoad);
                for (Fingerprint fingerprint : fingerprintsOfRoutersToLoadCopy) {
                    // one searched fingerprint
                    RouterImpl r = parsedServers.get(fingerprint);
                    if (r!=null && r.isValid()) {
                        // found valid descriptor
                        fingerprintsRouters.put(fingerprint, r);
                        fingerprintsOfRoutersToLoad.remove(fingerprint);
                    }
                }
            }
            log.info("loaded "+fingerprintsRouters.size()+" routers from local cache");
        }        
        
        // load from directory server
        final int TRHESHOLD_TO_LOAD_SINGE_ROUTER_DESCRITPIONS = 50;
        log.info("load "+fingerprintsOfRoutersToLoad.size()+" routers from dir server(s) - start");
        int successes = 0;
        if (fingerprintsOfRoutersToLoad.size()<=TRHESHOLD_TO_LOAD_SINGE_ROUTER_DESCRITPIONS) {
            // load the descriptions separately
            // TODO: implement it
            int attempts = fingerprintsOfRoutersToLoad.size();
            log.info("loaded "+successes+" of "+attempts+" missing routers from directory server(s) with multiple requests");
        } else {
            // load all description with one request (usually done during startup)
            List<RouterImpl> dirRouters = new ArrayList<RouterImpl>(getDirRouters());
            while (dirRouters.size()>0) {
                int i = rnd.nextInt(dirRouters.size());
                RouterImpl directoryServer = dirRouters.get(i);
                dirRouters.remove(i);
                if (directoryServer.getDirPort()<1) {
                    // cannot be used as directory server
                    continue;
                }
                allDescriptors = DescriptorFetcherThread.downloadAllDescriptors(directoryServer, lowerDirConnectionNetLayer);
    
                // split into single server descriptors
                if (allDescriptors!=null && allDescriptors.length()>=ALL_DESCRIPTORS_STR_MIN_LEN) {
                    Map<Fingerprint,RouterImpl> parsedServers = RouterImpl.parseRouterDescriptors(torConfig, allDescriptors);
                    int attempts = 0;
                    for (Fingerprint fingerprint : fingerprintsOfRoutersToLoad) {
                        // one searched fingerprint
                        RouterImpl r = parsedServers.get(fingerprint);
                        attempts++;
                        if (r!=null) {
                            // found search descriptor
                            fingerprintsRouters.put(fingerprint, r);
                            successes++;
                        }
                    }
                    log.info("loaded "+successes+" of "+attempts+" missing routers from directory server \""+directoryServer.getNickname()+"\" with single request");
                    break;
                }
            }
        }
        log.info("load routers from dir server(s), loaded "+successes+" routers - finished");
    }
    
    
    /**
     * Check whether the given route is compatible to the given restrictions
     * 
     * @param route
     *            a list of servers that form the route
     * @param sp
     *            the requirements to the route
     * @param forHiddenService
     *            set to TRUE to disregard exitPolicies
     * @return the boolean result
     */
    public boolean isCompatible(RouterImpl[] route, TCPStreamProperties sp, boolean forHiddenService) throws TorException {
        // check for null values
        if (route == null) {
            throw new TorException("received NULL-route");
        }
        if (sp == null) {
            throw new TorException("received NULL-sp");
        }
        if (route[route.length - 1] == null) {
            throw new TorException("route contains NULL at position " + (route.length - 1));
        }
        // empty route is always wrong
        if (route.length < 1) {
            return false;
        }
        // route is too short
        if (route.length < sp.getMinRouteLength()) {
            return false;
        }
        // route is too long
        if (route.length > sp.getMaxRouteLength())
            return false;

        // check compliance with sp.route
        Fingerprint[] proposedRoute = sp.getProposedRouteFingerprints();
        if (proposedRoute != null) {
            for (int i=0 ; (i<proposedRoute.length)&&(i<route.length)  ;++i) {
                if (proposedRoute[i]!=null) {
                    if (! route[i].getFingerprint().equals(proposedRoute[i])) {
                        return false;
                    }
                }
            }
        }
        
        if ((!forHiddenService) && (sp.isExitPolicyRequired())) {
            // check for exit policies of last node
            return route[route.length - 1].exitPolicyAccepts(sp.getAddr(), sp.getPort());
        } else {
            return true;
        }
    }

    /**
     * Exclude related nodes: family, class C and country (if specified in TorConfig)
     *
     * @param r node that should be excluded with all its relations
     * @return set of excluded node names
     */
    public Set<Fingerprint> excludeRelatedNodes(RouterImpl r){
        HashSet<Fingerprint> excludedServerfingerprints = new HashSet<Fingerprint>();
        HashSet<Fingerprint> myAddressNeighbours, myCountryNeighbours;

        if (TorConfig.routeUniqueClassC) {
            myAddressNeighbours = getAddressNeighbours(r.getAddress().getHostAddress());
            if (myAddressNeighbours != null)
                excludedServerfingerprints.addAll(myAddressNeighbours);
        } else {
            excludedServerfingerprints.add(r.getFingerprint());
        }
        
        // exclude all country insider, if desired
        if (TorConfig.routeUniqueCountry) {
            myCountryNeighbours = countryNeighbours.get(r.getCountryCode());
            if (myCountryNeighbours != null) {
                excludedServerfingerprints.addAll(myCountryNeighbours);
            }
        }
        // exclude its family as well
        excludedServerfingerprints.addAll(r.getFamily());

        return excludedServerfingerprints;
    }



    /** TODO: add doc: when is this used? */
    RouterImpl selectRandomNode(float p) {
        return selectRandomNode(validRoutersByFingerprint, new HashSet<Fingerprint>(), p);
    }

    /** TODO: add doc: when is this used? */
    public RouterImpl selectRandomNode(Map<Fingerprint, RouterImpl> torRouters, HashSet<Fingerprint> excludedServerFingerprints, float p) {
        float rankingSum = 0;
        RouterImpl myServer;
        excludedServerFingerprints.addAll(excludedNodesByConfig);
        // At first, calculate sum of the rankings
        Iterator<RouterImpl> it = torRouters.values().iterator();
        while (it.hasNext()) {
            myServer = it.next();
            if ((!excludedServerFingerprints.contains(myServer.getNickname())) && myServer.isDirv2Running()) {
                rankingSum += myServer.getRefinedRankingIndex(p);
            }
        }
        // generate a random float between 0 and rankingSum
        float serverRandom = rnd.nextFloat() * rankingSum;
        // select the server
        it = torRouters.values().iterator();
        while (it.hasNext()) {
            myServer = it.next();
            if ((!excludedServerFingerprints.contains(myServer.getNickname())) && myServer.isDirv2Running()) {
                serverRandom -= myServer.getRefinedRankingIndex(p);
                if (serverRandom <= 0) {
                    return myServer;
                }
            }
        }
        return null;
    }

    /**
     * Find a router by the give IP address and onoion port.
     * 
     * @param ipNetAddress
     * @param onionPort
     * @return the router; null if no valid matching router found 
     */
    public RouterImpl getValidRouterByIpAddressAndOnionPort(IpNetAddress ipNetAddress, int onionPort) {
        for (RouterImpl router : validRoutersByFingerprint.values()) {
            if (router.getOrAddress().equals(new TcpipNetAddress(ipNetAddress, onionPort))) {
                // router found
                return router;
            }
        }
        // not found
        return null;
    }

    /**
     * @return all valid routers with HSDir flag (hidden server directory), ordered by fingerprint
     */
    public RouterImpl[] getValidHiddenDirectoryServersOrderedByFingerprint() {
        // copy all hidden server directory to list
        List<RouterImpl> routersList;
        synchronized(allFingerprintsRouters) {
            routersList = new ArrayList<RouterImpl>(allFingerprintsRouters.values());
        }
        for (Iterator<RouterImpl> i=routersList.iterator(); i.hasNext();) {
            RouterImpl r = i.next();
            if ((!r.isDirv2HSDir()) || r.getDirPort()<1) {
                // no hidden server directory: remove it from the list
                i.remove();
            }
        }
        
        // copy list to array
        RouterImpl[] routers = (RouterImpl[])routersList.toArray(new RouterImpl[routersList.size()]);
        
        // order by fingerprint
        Comparator<RouterImpl> comp = new Comparator<RouterImpl>() {
            public int compare(RouterImpl o1, RouterImpl o2) {
                return o1.getFingerprint().compareTo(o2.getFingerprint());
            }
        };
        Arrays.sort(routers, comp);
        
        return routers;
    }

    /**
     * Get three directory servers (HSDir) needed to retrieve a hidden service descriptor
     * 
     * @param f    hidden service descriptor id
     * @return three consecutive routers that are hidden service directories with router.fingerprint>f
     */
    public Collection<RouterImpl> getThreeHiddenDirectoryServersWithFingerpringGreaterThan(Fingerprint f) {
        RouterImpl[] routers = getValidHiddenDirectoryServersOrderedByFingerprint();
        
        final int REQUESTED_NUM_OF_ROUTERS = 3;
        int numOfRoutersToFind = Math.min(REQUESTED_NUM_OF_ROUTERS, routers.length);
        Collection<RouterImpl> result = new ArrayList<RouterImpl>(numOfRoutersToFind);
        
        // find the first and the consecutive routers
        boolean takeNextRouters = false;
        for (int i=0; i<2*routers.length; i++) {
            RouterImpl r = routers[i%routers.length];

            // does it match?
            if (!takeNextRouters && r.getFingerprint().compareTo(f)>=0) {
                // yes
                takeNextRouters = true;
            }

            // take as part of the result?
            if (takeNextRouters) {
                // yes
                result.add(r);
                numOfRoutersToFind--;
                if (numOfRoutersToFind<=0) {
                    // the end
                    break;
                }
                continue;
            }
        }
        
        return result;
    }
    
    /**
     * Return the set of neighbors by address of the specific IP in the dotted notation
     */
    private HashSet<Fingerprint> getAddressNeighbours(String address) {
        String ipClassCString = Parsing.parseStringByRE(address, IPCLASSC_PATTERN, "");
        HashSet<Fingerprint> neighbours = addressNeighbours.get(ipClassCString);
        return neighbours;
    }

    /**
     * should be called when TorJava is closing
     */
    public void close() {
    }

    /**
     * for debugging purposes
     */
    void print() {
        if (log.isLoggable(Level.FINE)) {
            for (RouterImpl r : validRoutersByFingerprint.values()) {
                log.fine(r.toString());
            }
        }
    }


    public NetLayer getLowerDirConnectionNetLayer() {
        return lowerDirConnectionNetLayer;
    }


    public void setLowerDirConnectionNetLayer(NetLayer lowerDirConnectionNetLayer) {
        this.lowerDirConnectionNetLayer = lowerDirConnectionNetLayer;
    }


    public Map<Fingerprint, RouterImpl> getValidRoutersByFingerprint() {
        return validRoutersByFingerprint;
    }


    public void setValidRoutersByFingerprint(Map<Fingerprint, RouterImpl> validRoutersByFingerprint) {
        this.validRoutersByFingerprint = validRoutersByFingerprint;
    }
 }


