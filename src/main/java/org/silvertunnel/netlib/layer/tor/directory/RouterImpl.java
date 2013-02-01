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
package org.silvertunnel.netlib.layer.tor.directory;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.layer.tor.api.Fingerprint;
import org.silvertunnel.netlib.layer.tor.api.Router;
import org.silvertunnel.netlib.layer.tor.api.RouterExitPolicy;
import org.silvertunnel.netlib.layer.tor.common.LookupServiceUtil;
import org.silvertunnel.netlib.layer.tor.common.TorConfig;
import org.silvertunnel.netlib.layer.tor.util.Encoding;
import org.silvertunnel.netlib.layer.tor.util.Encryption;
import org.silvertunnel.netlib.layer.tor.util.Parsing;
import org.silvertunnel.netlib.layer.tor.util.TorException;
import org.silvertunnel.netlib.layer.tor.util.Util;

/**
 * a compound data structure that keeps track of the static informations we have
 * about a single Tor server.
 * 
 * @author Lexi Pimenidis
 * @author Andriy Panchenko
 * @author Michael Koellejan
 * @author hapke
 */
public class RouterImpl implements Router, Cloneable {
    private static final Logger log = Logger.getLogger(RouterImpl.class.getName());
    
    TorConfig torConfig;
    
    /**
     * The raw router descriptor which has been handed to us. 
     * In the normal case we just return this stored descriptor.
     */
    private String routerDescriptor;

    /** Information extracted from the Router descriptor. */
    private String nickname; 
    /** ip or hostname */
    private String hostname;
    /** the resolved hostname */
    private InetAddress address;
    /** country code where it is located */
    private String countryCode;

    private int orPort;
    private int socksPort;
    private int dirPort;

    private int bandwidthAvg;
    private int bandwidthBurst;
    private int bandwidthObserved;
 
    private String platform;
    private Date published;

    private Fingerprint fingerprint;
    private Fingerprint v3ident;

    private int uptime;
    
    private RSAPublicKey onionKey;
    private RSAPrivateKey onionKeyPrivate;
    
    private RSAPublicKey signingKey;
    private RSAPrivateKey signingKeyPrivate;
  
    private RouterExitPolicy[] exitpolicy;

    private byte[] routerSignature;
    private String contact;
    
    /** Fingerprints of the routers of the family */
    private Set<String/*TODO: Fingerprint*/> family = new HashSet<String>();
    
    /** based on the time of loading this data */
    private Date validUntil;
    
    /** FIXME: read-history, write-history not implemented */
    private static final int MAX_EXITPOLICY_ITEMS = 300;

    // Additional information for V2-Directories
    private Date lastUpdate;
    private boolean dirv2Authority = false;
    private boolean dirv2Exit = false;
    private boolean dirv2Fast = false;
    private boolean dirv2Guard = false;
    private boolean dirv2Named = false;
    private boolean dirv2Stable = false;
    private boolean dirv2Running = false;
    private boolean dirv2Valid = false;
    private boolean dirv2V2dir = false;
    private boolean dirv2HSDir = false;

    /** internal Server-Ranking data */
    private float rankingIndex;
    /** see updateServerRanking() */
    private static final int highBandwidth = 2097152; 
    /** see updateServerRanking() */
    private static final float alpha = 0.6f;
    /** coefficient to decrease server ranking if the server fails to respond in time */
    private static final float punishmentFactor = 0.75f;

    // patterns used to parse a router descriptor
    private static Pattern ROUTER_PATTERN;
    private static Pattern PLATFORM_PATTERN ;
    private static Pattern PUBLISHED_PATTERN;
    private static Pattern UPTIME_PATTERN;
    private static Pattern FINGERPRINT_PATTERN;
    private static Pattern CONTACT_PATTERN;
    private static Pattern ROUTER_PATTERN2;
    private static Pattern ONIONKEY_PATTERN;
    private static Pattern SIGNINGKEY_PATTERN;
    private static Pattern STRINGFAMILY_PATTERN;
    private static Pattern STRINGOPTFAMILY_PATTERN_PATTERN;
    private static Pattern PFAMILY_PATTERN;
    private static Pattern ROUTERSIGNATURE_PATTERN;
    private static Pattern SHA1INPUT_PATTERN;

    {
        // initialize patterns,
        // do it here to be able to log exceptions
        try {
            ROUTER_PATTERN = Parsing.compileRegexPattern("^router (\\w+) (\\S+) (\\d+) (\\d+) (\\d+)");
            PLATFORM_PATTERN = Parsing.compileRegexPattern("^platform (.*?)$");
            PUBLISHED_PATTERN = Parsing.compileRegexPattern("^published (.*?)$");
            UPTIME_PATTERN = Parsing.compileRegexPattern("^uptime (\\d+)");
            FINGERPRINT_PATTERN = Parsing.compileRegexPattern("^(?:opt )?fingerprint (.*?)$");
            CONTACT_PATTERN = Parsing.compileRegexPattern("^contact (.*?)$");
            ROUTER_PATTERN2 = Parsing.compileRegexPattern("^bandwidth (\\d+) (\\d+) (\\d+)?");
            ONIONKEY_PATTERN = Parsing.compileRegexPattern("^onion-key\n(.*?END RSA PUBLIC KEY......)");
            SIGNINGKEY_PATTERN = Parsing.compileRegexPattern("^signing-key\n(.*?END RSA PUBLIC KEY-----\n)");
            STRINGFAMILY_PATTERN = Parsing.compileRegexPattern("^family (.*?)$");
            STRINGOPTFAMILY_PATTERN_PATTERN = Parsing.compileRegexPattern("^opt family (.*?)$");
            PFAMILY_PATTERN = Pattern.compile("(\\S+)");
            ROUTERSIGNATURE_PATTERN = Parsing.compileRegexPattern("^router-signature\n-----BEGIN SIGNATURE-----(.*?)-----END SIGNATURE-----");
            SHA1INPUT_PATTERN = Parsing.compileRegexPattern("^(router .*?router-signature\n)");
        } catch (Exception e) {
            log.log(Level.SEVERE, "could not initialize all patterns", e);
        }
    }
    private static final int MAX_ROUTERDESCRIPTOR_LENGTH = 10000;

    /**
     * takes a router descriptor as string
     * 
     * @param routerDescriptor
     *            a router descriptor to initialize the object from
     */
    RouterImpl(TorConfig torConfig, String routerDescriptor) throws TorException {
        if (torConfig == null) {
            throw new TorException("torConfig is null");
        }
        if (routerDescriptor.length()>MAX_ROUTERDESCRIPTOR_LENGTH) {
            throw new TorException("skipped router with routerDescriptor of length="+routerDescriptor.length());
        }
        
        
        this.torConfig = torConfig;
        init();
        parseRouterDescriptor(routerDescriptor);
        updateServerRanking();

        this.countryCode = LookupServiceUtil.getCountryCodeOfIpAddress(this.address);
    }

    /**
     * Special constructor for hidden service: Faked server in connectToHidden().
     * @param pk
     * @throws TorException
     */
    public RouterImpl(TorConfig torConfig,RSAPublicKey pk) throws TorException {
        if (torConfig == null) {
            throw new TorException("torConfig is null");
        }

        this.torConfig = torConfig;
        init();
        onionKey = pk;
        //this.countryCode = LookupServiceUtil.getCountryCodeOfIpAddress(this.address);
        this.countryCode = "--";
    }

    /**
     * takes input data and initializes the server object with it. A router
     * descriptor and a signature will be automatically generated.
     */
    RouterImpl(TorConfig torConfig, String nickname, InetAddress address, int orPort, int dirPort,
            Fingerprint v3ident, Fingerprint fingerprint) throws TorException    {
        if (torConfig == null) {
            throw new TorException("torConfig is null");
        }
        // Set member variables.
        this.torConfig = torConfig;
        this.nickname = nickname;
        this.address = address;
        this.hostname = address.getHostAddress();
        
        this.orPort = orPort;
        this.dirPort = dirPort;
        this.fingerprint = fingerprint.cloneReliable();
        this.v3ident = (v3ident==null) ? null : v3ident.cloneReliable();
    }

    /**
     * takes input data and initializes the server object with it. A router
     * descriptor and a signature will be automatically generated.
     */
    RouterImpl(TorConfig torConfig,String varNickname, InetAddress varAddress, int varOrPort, int varSocksPort,
            int varDirPort, int varBandwidthAvg, int varBandwidthBurst,
            int varBandwidthObserved, Fingerprint varfingerprint, int varInitialUptime,
            RSAPublicKey varOnionKey, RSAPrivateKey varOnionKeyPrivate, 
            RSAPublicKey varSigningKey, RSAPrivateKey varSigningKeyPrivate,
            RouterExitPolicy[] varExitpolicy, String varContact, HashSet<String> varFamily) 
            throws TorException
        {
        if (torConfig == null) {
            throw new TorException("torConfig is null");
        }
        
        // Set member variables.
        this.torConfig = torConfig;
        this.nickname = varNickname;
        this.address = varAddress;
        this.hostname = varAddress.getHostAddress();
        
        this.orPort = varOrPort;
        this.socksPort = varSocksPort;
        this.dirPort = varDirPort;
        
        this.bandwidthAvg = varBandwidthAvg;
        this.bandwidthBurst = varBandwidthBurst;
        this.bandwidthObserved = varBandwidthObserved;

        this.platform = Util.MYNAME + " on " + TorConfig.operatingSystem();
       
        this.published = new Date(System.currentTimeMillis());
        this.fingerprint = varfingerprint.cloneReliable();
        this.uptime = varInitialUptime;
        
        this.onionKey = varOnionKey;
        this.onionKeyPrivate = varOnionKeyPrivate;
        this.signingKey = varSigningKey;
        this.signingKeyPrivate = varSigningKeyPrivate;

        this.exitpolicy = varExitpolicy;

        this.contact = varContact;
        
        this.family = varFamily;
        
        // Render router descriptor
        this.routerDescriptor = renderRouterDescriptor();
        this.countryCode = LookupServiceUtil.getCountryCodeOfIpAddress(this.address);
    }

    /** Constructor-indepentent initialization **/
    private void init() {
         // unknown/new
        rankingIndex = -1;
    }

    /**
     *  wrapper from server-flags of dir-spec v1 to dir-spec v2
     */
    void updateServerStatus(boolean alive,boolean trusted) {
      dirv2Running = alive;
      dirv2Exit = trusted;
      dirv2Guard = trusted;
      dirv2Valid = trusted;
    }
    
    /**
     * Update this server's status
     * 
     * @param flags string containing flags
     */
    void updateServerStatus(String flags) {
      if (flags.contains("Running"))     dirv2Running = true; 
      if (flags.contains("Exit"))           dirv2Exit = true; 
      if (flags.contains("Authority")) dirv2Authority = true;
      if (flags.contains("Fast"))           dirv2Fast = true;
      if (flags.contains("Guard"))         dirv2Guard = true;
      if (flags.contains("Stable"))       dirv2Stable = true;
      if (flags.contains("Named"))         dirv2Named = true;
      if (flags.contains("V2Dir"))         dirv2V2dir = true;
      if (flags.contains("Valid"))         dirv2Valid = true;
      if (flags.contains("HSDir"))         dirv2HSDir = true;
    }

    /**
     * @return the regular expression that can be evaluated by the
     *         initialisation function
     */
    static String regularExpression() {
        return "(router (\\w+) \\S+ \\d+ \\d+.*?END SIGNATURE-----\n)";
    }
    
    /**
     * Clone, but do not throw an exception.
     */
    public RouterImpl cloneReliable() throws RuntimeException {
        try {
            return (RouterImpl)clone();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * This function parses the exit policy items from the router descriptor.
     * 
     * @param routerDescriptor
     *            a router descriptor with exit policy items.
     * @return the complete exit policy
     */
    private RouterExitPolicy[] parseExitPolicy(String routerDescriptor) {
        ArrayList<RouterExitPolicy> epList = new ArrayList<RouterExitPolicy>(30);
        RouterExitPolicy ep;

        Pattern p = Pattern.compile("^(accept|reject) (.*?):(.*?)$",
                Pattern.DOTALL + Pattern.MULTILINE + Pattern.CASE_INSENSITIVE
                        + Pattern.UNIX_LINES);
        Matcher m = p.matcher(routerDescriptor);

        // extract all exit policies from description
        int nr = 0;
        while (m.find() && (nr < MAX_EXITPOLICY_ITEMS)) {
            boolean epAccept;
            long epIp;
            long epNetmask;
            int epLoPort;
            int epHiPort;
            epAccept = m.group(1).equals("accept");
            // parse network
            String network = m.group(2);
            epIp = 0;
            epNetmask = 0;
            if (!network.equals("*")) {
                int slash = network.indexOf("/");
                if (slash >= 0) {
                    epIp = Encoding.dottedNotationToBinary(network.substring(0,
                            slash));
                                        String netmask = network.substring(slash + 1);
                                        if (netmask.indexOf(".")>-1)
                                            epNetmask = Encoding.dottedNotationToBinary(netmask);
                                        else epNetmask = (((0xffffffffL << (32-(Integer.parseInt(netmask))))) & 0xffffffffL);
                } else {
                    epIp = Encoding.dottedNotationToBinary(network);
                    epNetmask = 0xffffffff;
                }
            }
            epIp = epIp & epNetmask;
            // parse port range
            if (m.group(3).equals("*")) {
                epLoPort = 0;
                epHiPort = 65535;
            } else {
                int dash = m.group(3).indexOf("-");
                if (dash > 0) {
                    epLoPort = Integer
                            .parseInt(m.group(3).substring(0, dash));
                    epHiPort = Integer.parseInt(m.group(3)
                            .substring(dash + 1));
                } else {
                    epLoPort = Integer.parseInt(m.group(3));
                    epHiPort = epLoPort;
                }
                ;
            }
            ;
            ++nr;
            epList.add(new RouterExitPolicyImpl(epAccept, epIp, epNetmask, epLoPort, epHiPort));
        }

        return (RouterExitPolicy[]) (epList.toArray(new RouterExitPolicy[epList.size()]));
    }

    /**
     * parse multiple router descriptors from one String.
     * 
     * @param tor
     * @param routerDescriptors
     * @return the result; if multiple entries with the same fingerprint are in routerDescriptors,
     *         the last be be considered
     */
    public static Map<Fingerprint,RouterImpl> parseRouterDescriptors(TorConfig torConfig, String routerDescriptors) {
        Map<Fingerprint,RouterImpl> result = new HashMap<Fingerprint,RouterImpl>();

        // split into single server descriptors
        Pattern p = Pattern.compile(
                "^(router.*?END SIGNATURE-----)", Pattern.DOTALL
                        + Pattern.MULTILINE + Pattern.CASE_INSENSITIVE
                        + Pattern.UNIX_LINES);
        Matcher m = p.matcher(routerDescriptors);
        while (m.find()) {
            // parse single descriptor 
            try {
                String singleDescriptor = m.group(1);
                
                // avoid reference to the very big routerDescriptors String:
                singleDescriptor = new String(singleDescriptor);
                
                // parse and store a single router
                RouterImpl singleServer = new RouterImpl(torConfig, singleDescriptor);
                result.put(singleServer.fingerprint, singleServer);
            } catch (TorException e) {
                log.log(Level.INFO, ""+e);
            } catch (Exception e) {
                log.log(Level.INFO, "unexpected", e);
            }
        }
            
        return result;
    }
    
    
    /**
     * extracts all relevant information from the router descriptor and saves it
     * in the member variables.
     * 
     * @param rd
     *            string encoded router descriptor
     */
    private void parseRouterDescriptor(String rd)
            throws TorException {
        this.routerDescriptor = rd;

        // Router item: nickname, hostname, onion-router-port, socks-port, dir-port
        Matcher m = ROUTER_PATTERN.matcher(rd);
        m.find();

        
        this.nickname = m.group(1);

        this.hostname = m.group(2);
        this.orPort = Integer.parseInt(m.group(3));
        this.socksPort = Integer.parseInt(m.group(4));
        this.dirPort = Integer.parseInt(m.group(5));

        // secondary information
        platform = Parsing.parseStringByRE(rd, PLATFORM_PATTERN, "unknown");
        published = Util.parseUtcTimestamp(Parsing.parseStringByRE(rd, PUBLISHED_PATTERN, ""));
        validUntil = new Date(published.getTime()+TorConfig.ROUTER_DESCRIPTION_VALID_PERIOD_MS);
        uptime = Integer.parseInt(Parsing.parseStringByRE(rd, UPTIME_PATTERN, "0"));
        try {
            fingerprint = new FingerprintImpl(Encoding.parseHex(Parsing.parseStringByRE(rd, FINGERPRINT_PATTERN, "")));
        } catch (Exception e) {
                throw new TorException("Server " + nickname + " skipped as router");
        }
        contact = Parsing.parseStringByRE(rd, CONTACT_PATTERN, "");

        // make that IF description is from a trusted server, that fingerprint is correct
        /* not needed:
                if (tor.config.trustedServers.containsKey(nickname)) {
                    String fingerprintFromConfig = (String) (tor.config.trustedServers.get(nickname)).get("fingerprint");
                    if (!fingerprint.getHex().equalsIgnoreCase(fingerprintFromConfig))
                        throw new TorException("Server " + nickname + " is trusted, but fingerprint check failed");
                }
        */
        
        // bandwidth
        m = ROUTER_PATTERN2.matcher(rd);
        if (m.find()) {
            bandwidthAvg = Integer.parseInt(m.group(1));
            bandwidthBurst = Integer.parseInt(m.group(2));
            bandwidthObserved = Integer.parseInt(m.group(3));
        }

        // onion key
        String stringOnionKey = Parsing.parseStringByRE(rd, ONIONKEY_PATTERN, "");
        onionKey = Encryption.extractPublicRSAKey(stringOnionKey);

        // signing key
        String stringSigningKey = Parsing.parseStringByRE(rd, SIGNINGKEY_PATTERN, "");
        signingKey = Encryption.extractPublicRSAKey(stringSigningKey);

        // verify signing-key against fingerprint
        try {
            byte[] pkcs = Encryption.getPKCS1EncodingFromRSAPublicKey(signingKey);
            byte[] keyHash = Encryption.getDigest(pkcs);
            if (!new FingerprintImpl(keyHash).equals(fingerprint)) {
                throw new TorException("Server " + nickname + " doesn't verify signature vs fingerprint");
            }
        } catch (TorException e) {
            throw e;
        } catch (Exception e) {
            throw new TorException("Server " + nickname
                    + " doesn't verify signature vs fingerprint");
        }

        // parse family
        String stringFamily = Parsing.parseStringByRE(rd, STRINGFAMILY_PATTERN, "");
        if (stringFamily.length()==0) {
            stringFamily = Parsing.parseStringByRE(rd, STRINGOPTFAMILY_PATTERN_PATTERN, "");
        }
        Matcher mFamily = PFAMILY_PATTERN.matcher(stringFamily);
        while (mFamily.find()) {
            String host = mFamily.group(1);
            family.add(host);
        }

        // check the validity of the signature    
        routerSignature = Encoding.parseBase64(Parsing.parseStringByRE(rd, ROUTERSIGNATURE_PATTERN, ""));
        byte[] sha1Input = (Parsing.parseStringByRE(rd, SHA1INPUT_PATTERN, "")).getBytes();
        if (!Encryption.verifySignature(routerSignature, signingKey, sha1Input)) {
            log.info("Server -> router-signature check failed for " + nickname);
            throw new TorException("Server " + nickname + ": description signature verification failed");
        }

        // exit policy
        exitpolicy = parseExitPolicy(rd);
        // usually in directory the hostname is already set to the IP
        // so, following resolve just converts it to the InetAddress
        try {
            address = InetAddress.getByName(hostname); 
        } catch (UnknownHostException e) {
            throw new TorException("Server.ParseRouterDescriptor: Unresolvable hostname " + hostname);
        }
    }

    /**
     * converts exit policy objects back into an item
     * 
     * @param ep
     *            an array of exit-policy objects.
     * @return an exit policy item.
     * 
     */
    private String renderExitPolicy(RouterExitPolicy[] ep) {
        StringBuffer rawPolicy = new StringBuffer();

        for (int i = 0; i < ep.length; i++) {
            if (ep[i].isAccept())
                rawPolicy.append("accept ");
            else
                rawPolicy.append("reject ");

            if (ep[i].getNetmask() == 0 && ep[i].getIp() == 0) {
                rawPolicy.append("*");
            } else {
                if (ep[i].getNetmask() == 0xffffffff) {
                    rawPolicy.append(Encoding.binaryToDottedNotation(ep[i].getIp()));
                } else {
                    rawPolicy.append(Encoding.binaryToDottedNotation(ep[i].getIp()));
                    rawPolicy.append("/"
                                                        + Encoding.netmaskToInt(ep[i].getNetmask()));
                }
            }

            rawPolicy.append(":");

            if (ep[i].getLoPort() == 0 && ep[i].getHiPort() == 65535) {
                rawPolicy.append("*");
            } else {
                if (ep[i].getLoPort() == ep[i].getHiPort()) {
                    rawPolicy.append(ep[i].getLoPort());
                } else {
                    rawPolicy.append(ep[i].getLoPort() + "-" + ep[i].getHiPort());
                }
            }

            rawPolicy.append("\n");
        }

        return rawPolicy.toString();
    }

    /**
     * renders a router descriptor from member variables
     * 
     * @return router descriptor in extensible information format
     */
    String renderRouterDescriptor() {
        StringBuffer rawServer = new StringBuffer();

        rawServer.append("router " + nickname + " " + address.getHostAddress() + " " + orPort + " " + socksPort + " " + dirPort + "\n");
        rawServer.append("platform " + platform + "\n");

        rawServer.append("published(UTC) " + Util.formatUtcTimestamp(published) + "\n");
        rawServer.append("opt fingerprint " + fingerprint.getHexWithSpaces() + "\n");
        if (uptime != 0) {
            rawServer.append("uptime " + uptime + "\n");
        }
        rawServer.append("bandwidth " + bandwidthAvg + " " + bandwidthBurst + " " + bandwidthObserved + "\n");

        rawServer.append("onion-key\n" + Encryption.getPEMStringFromRSAPublicKey(onionKey) + "\n");

        rawServer.append("signing-key\n" + Encryption.getPEMStringFromRSAPublicKey(signingKey) + "\n");

        String stringFamily = "";
        Iterator<String> familyIterator = family.iterator();
        while (familyIterator.hasNext()) {
            stringFamily += " " + familyIterator.next();
        }

        rawServer.append("opt family" + stringFamily + "\n");

        if (contact != "") {
            rawServer.append("contact " + contact + "\n");
        }
        log.info("xxxxx2 contact.length="+contact.length());

        rawServer.append(renderExitPolicy(exitpolicy));

        // sign data
        rawServer.append("router-signature\n");

        rawServer.append("directory-signature " + torConfig.nickname + "\n");
        byte[] data = rawServer.toString().getBytes();
        rawServer.append(Encryption.binarySignatureToPEM(Encryption.signData(data, signingKeyPrivate)));

        return rawServer.toString();
    }

    /**
     * updates the server ranking index
     * 
     * Is supposed to be between 0 (undesirable) and 1 (very desirable). Two
     * variables are taken as input:
     * <ul>
     * <li> the uptime
     * <li> the bandwidth
     * <li> if available: the previous ranking
     * </ul>
     */
    private void updateServerRanking() {
        float rankingFromDirectory = (Math.min(1, uptime / 86400) + Math.min(1,
                (bandwidthAvg * alpha + bandwidthObserved * (1 - alpha))
                        / highBandwidth)) / 2; // 86400 is uptime of 24h
        // build over-all ranking from old value (if available) and new 
        if (rankingIndex<0) {
            rankingIndex = rankingFromDirectory;
        } else {
            rankingIndex = rankingFromDirectory *(1-TorConfig.rankingTransferPerServerUpdate)  + 
                           rankingIndex         *   TorConfig.rankingTransferPerServerUpdate;
        }
        
        if (log.isLoggable(Level.FINER)) {
            log.finer("Server.updateServerRanking: "+nickname+" is ranked "+rankingIndex);
        }
    }

    /**
     * returns ranking index taking into account user preference
     * 
     * @param p
     *            user preference (importance) of considering ranking index
     *            <ul>
     *            <li> 0 select hosts completely randomly
     *            <li> 1 select hosts with good uptime/bandwidth with higher
     *            prob.
     *            </ul>
     */
    float getRefinedRankingIndex(float p) {
        // align all ranking values to 0.5, if the user wants to choose his
        // servers
        // from a uniform probability distribution
        return (rankingIndex * p + TorConfig.rankingIndexEffect * (1 - p));
    }

    /**
     * decreases rankingIndex by the punishmentFactor
     */
    public void punishRanking() {
        rankingIndex *= punishmentFactor;
    }

    /**
     * can be used to query the exit policies wether this server would allow
     * outgoing connections to the host and port as given in the parameters.
     * <b>IMPORTANT:</b> this routing must be able to work, even if <i>addr</i>
     * is not given!
     * 
     * @param addr
     *            the host that someone wants to connect to
     * @param port
     *            the port that is to be connected to
     * @return a boolean value wether the conenction would be allowed
     */
    public boolean exitPolicyAccepts(InetAddress addr, int port) {
        long ip;
        if (addr != null) { // set IP as given
            byte[] temp1 = addr.getAddress();
            long[] temp = new long[4];
            for (int i = 0; i < 4; ++i) {
                temp[i] = temp1[i];
                if (temp[i] < 0)
                    temp[i] = 256 + temp[i];
            }
            ;
            ip = ((temp[0] << 24) | (temp[1] << 16) | (temp[2] << 8) | temp[3]);
        } else {
            // HACK: if no IP and port is given, always return true
            if (port == 0)
                return true;
            // HACK: if no IP is given, use only exits that allow ALL ip-ranges
            // this should possibly be replaced by some other way of checking it
            ip = 0xffffffffL;
        }
        ;
    
        for (int i = 0; i < exitpolicy.length; ++i) {
            if ((exitpolicy[i].getLoPort() <= port)
                    && (exitpolicy[i].getHiPort() >= port)
                    && (exitpolicy[i].getIp() == (ip & exitpolicy[i].getNetmask()))) {
                return exitpolicy[i].isAccept();
            }
            ;
        }
        ;
        return false;
    }

    /**
     * @return can this server be used as a directory-server?
     */
    boolean isDirServer() {
        return (dirPort > 0);
    }

    /**
     * used for debugging purposes
     * 
     * @param b
     *            an array t be printed in hex
     */
    private String toStringArray(byte[] b) {
        String hex = "0123456789abcdef";
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < b.length; ++i) {
            int x = b[i];
            if (x < 0)
                x = 256 + x; // why are there no unsigned bytes in java?
            sb.append(hex.substring(x >> 4, (x >> 4) + 1));
            sb.append(hex.substring(x % 16, (x % 16) + 1));
            sb.append(" ");
        }
        return sb.toString();
    }

    /**
     * used for debugging purposes
     */
    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("router=" + nickname);
        sb.append(","+hostname);
        sb.append("," + fingerprint);
        return sb.toString();
    }

    /**
     * used for debugging purposes
     */
    public String toLongString() {
        StringBuffer sb = new StringBuffer();
        sb.append("---- " + nickname + " (" + contact + ")\n");
        sb.append("hostname:" + hostname + "\n");
        sb.append("or port:" + orPort + "\n");
        sb.append("socks port:" + socksPort + "\n");
        sb.append("dirserver port:" + dirPort + "\n");
        sb.append("platform:" + platform + "\n");
        sb.append("published:" + published + "\n");
        sb.append("uptime:" + uptime + "\n");
        sb.append("bandwidth: " + bandwidthAvg + " " + bandwidthBurst
                + " " + bandwidthObserved + "\n");
        sb.append("fingerprint:" + fingerprint + "\n");
        sb.append("validUntil:" + validUntil + "\n");
        sb.append("onion key:" + onionKey + "\n");
        sb.append("signing key:" + signingKey + "\n");
        sb.append("signature:" + toStringArray(routerSignature) + "\n");
        sb.append("exit policies:" + "\n");
        for (int i = 0; i < exitpolicy.length; ++i) {
            sb.append("  ").append(exitpolicy[i]).append("\n");
        }
        return sb.toString();
    }
    
    /**
     * Check if the router description is still valid.
     */
    public boolean isValid() {
        if (validUntil==null) {
            return false;
        }
        
        Date now = new Date();
        return  validUntil.after(now); 
    }
    
    /**
     * @return address + directory port
     */
    public TcpipNetAddress getDirAddress() {
        byte[] ipaddress = address.getAddress();
        if (ipaddress!=null) {
            return new TcpipNetAddress(ipaddress, dirPort);
        } else {
            return new TcpipNetAddress(address.getHostName(), dirPort);
        }
    }

    /**
     * @return address + or port
     */
    public TcpipNetAddress getOrAddress() {
        byte[] ipaddress = address.getAddress();
        if (ipaddress!=null) {
            return new TcpipNetAddress(ipaddress, orPort);
        } else {
            return new TcpipNetAddress(address.getHostName(), orPort);
        }
    }

    ///////////////////////////////////////////////////////
    // generated getters and setters
    ///////////////////////////////////////////////////////
 
    public String getNickname() {
        return nickname;
    }

    public String getHostname() {
        return hostname;
    }

    public InetAddress getAddress() {
        return address;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public int getOrPort() {
        return orPort;
    }

    public int getSocksPort() {
        return socksPort;
    }

    public int getDirPort() {
        return dirPort;
    }

    public int getBandwidthAvg() {
        return bandwidthAvg;
    }

    public int getBandwidthBurst() {
        return bandwidthBurst;
    }

    public int getBandwidthObserved() {
        return bandwidthObserved;
    }

    public String getPlatform() {
        return platform;
    }

    public Date getPublished() {
        return published;
    }

    public Fingerprint getFingerprint() {
        return fingerprint;
    }

    public Fingerprint getV3Ident() {
        return v3ident;
    }

    public int getUptime() {
        return uptime;
    }
    public RSAPublicKey getOnionKey() {
        return onionKey;
    }

    public RSAPublicKey getSigningKey() {
        return signingKey;
    }

    public RouterExitPolicy[] getExitpolicy() {
        return exitpolicy;
    }

    public String getContact() {
        return contact;
    }

    public Set<Fingerprint> getFamily() {
        // TODO:
        return new HashSet<Fingerprint>();
    }

    public Date getValidUntil() {
        return validUntil;
    }

    public Date getLastUpdate() {
        return lastUpdate;
    }

    public boolean isDirv2Authority() {
        return dirv2Authority;
    }

    public void setDirv2Authority(boolean dirv2Authority) {
        this.dirv2Authority = dirv2Authority;
    }

    public boolean isDirv2Exit() {
        return dirv2Exit;
    }

    public void setDirv2Exit(boolean dirv2Exit) {
        this.dirv2Exit = dirv2Exit;
    }

    public boolean isDirv2Fast() {
        return dirv2Fast;
    }

    public void setDirv2Fast(boolean dirv2Fast) {
        this.dirv2Fast = dirv2Fast;
    }

    public boolean isDirv2Guard() {
        return dirv2Guard;
    }

    public void setDirv2Guard(boolean dirv2Guard) {
        this.dirv2Guard = dirv2Guard;
    }

    public boolean isDirv2Named() {
        return dirv2Named;
    }

    public void setDirv2Named(boolean dirv2Named) {
        this.dirv2Named = dirv2Named;
    }

    public boolean isDirv2Stable() {
        return dirv2Stable;
    }

    public void setDirv2Stable(boolean dirv2Stable) {
        this.dirv2Stable = dirv2Stable;
    }

    public boolean isDirv2Running() {
        return dirv2Running;
    }

    public void setDirv2Running(boolean dirv2Running) {
        this.dirv2Running = dirv2Running;
    }

    public boolean isDirv2Valid() {
        return dirv2Valid;
    }

    public void setDirv2Valid(boolean dirv2Valid) {
        this.dirv2Valid = dirv2Valid;
    }

    public boolean isDirv2V2dir() {
        return dirv2V2dir;
    }

    public void setDirv2V2dir(boolean dirv2V2dir) {
        this.dirv2V2dir = dirv2V2dir;
    }

    /**
     * @return true=if the router is considered a v2 hidden service directory
     */
    public boolean isDirv2HSDir() {
        return dirv2HSDir;
    }

    public float getRankingIndex() {
        return rankingIndex;
    }

    public void setRankingIndex(float rankingIndex) {
        this.rankingIndex = rankingIndex;
    }

    public static int getHighBandwidth() {
        return highBandwidth;
    }

    public String getRouterDescriptor() {
        return routerDescriptor;
    }
}
