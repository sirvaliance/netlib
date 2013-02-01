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

package org.silvertunnel.netlib.layer.tor.common;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.silvertunnel.netlib.layer.tor.util.Encoding;
import org.silvertunnel.netlib.layer.tor.util.Parsing;
import org.silvertunnel.netlib.layer.tor.util.Util;


/**
 * Global configuration of TorNetLayer.
 * 
 * @author Lexi
 * @author Michael Koellejan
 * @author Andriy Panchenko
 * @author hapke
 */
public class TorConfig {
    private static final Logger log = Logger.getLogger(TorConfig.class.getName());
    
    // functionality
    public static int cacheMaxAgeSeconds = 24 * 3600;
    public static int startupDelaySeconds = 45;
    /** for running an own directory server */ 
    public static int dirserverPort = 0; 
    /** for running an own onion router */
    public static int orPort = 0;
    
    public String nickname = Util.MYNAME;

    // QoS-parameters
    public static int retriesConnect = 5;
    
    public static int reconnectCircuit = 3;
    public static int retriesStreamBuildup = 5;

    /** TODO was: 11 */
    public static int defaultIdleCircuits = 10;
    /** TODO: is 5 but was 11 */
    public static int minimumIdleCircuits = 5;
    public static final String TOR_SYSTEMPROPERTY_torMinimumIdleCircuits = "torMinimumIdleCircuits";

    public static int queueTimeoutCircuit = 40;
    public static int queueTimeoutResolve = 20;
    /** TODO was: 11 */
    public static int queueTimeoutStreamBuildup = 5;

    public static int circuitClosesOnFailures = 3;
    public static int circuitsMaximumNumber = 30; 
    public static long maxAllowedSetupDurationMs = 10000; 
    public static final String TOR_SYSTEMPROPERTY_torMaxAllowedSetupDurationMs = "torMaxAllowedSetupDurationMs";
    
    /** 0..1 */
    public static float rankingTransferPerServerUpdate = 0.95f;

    /** this is a truly asocial way of building streams!! */
    public static boolean veryAggressiveStreamBuilding = false;

    // directory parameters
    /** in minutes longer, since it updates the complete directory at once */
    public static int intervalDirectoryV1Refresh = 30;
    /** in minutes */
    public static int intervalDirectoryRefresh = 2;
    /** set to <=0 to read all */
    public static int dirV2ReadMaxNumberOfDescriptorsFirstTime = 180;
    /** set to <=0 to read all */
    public static int dirV2ReadMaxNumberOfDescriptorsPerUpdate = 80;
    public static int dirV2ReadMaxNumberOfThreads = 10; 
    /** per descriptor */
    public static int dirV2ReloadRetries = 3;
    /** in seconds */
    public static int dirV2ReloadTimeout = 120;
    public static int dirV2DescriptorsPerBatch = 1;
    /** in millisecond */
    public static int dirV2NetworkStatusRequestTimeOut = 120000;
    
    /** to access directory servers: connect timeout: 1 minute */ 
    public static long DIR_CONNECT_TIMEOUT_MILLIS = 60L*1000L;
    /** to access directory servers:  max. connection timeout: 60 minutes */
    public static long DIR_OVERALL_TIMEOUT_MILLIS = 60L*60L*1000L;
    /** to access directory servers: max. bytes to transfer (to avoid endless transfers and out-of-memory problems): 50 MByte */ 
    public static long DIR_MAX_FILETRANSFER_BYTES = 50L*1024L*1024L;
    /** to access directory servers: minimum throughput: 15 KBytes / 15 seconds */ 
    public static long DIR_THROUGPUT_TIMEFRAME_MIN_BYTES = 15L*1024L;
    //public static long DIR_THROUGPUT_TIMEFRAME_MIN_BYTES = 6000L*1024L;// TODO: "very fast" parameter 
    /** to access directory servers: minimum throughput: 15 KBytes / 15 seconds */ 
    public static long DIR_THROUGPUT_TIMEFRAME_MILLIS = 15L*1000L;
    //public static long DIR_THROUGPUT_TIMEFRAME_MILLIS = 1L*1000L; // TODO: "very fast" parameter 

    /** to access servers via Tor: connect timeout: 3 minutes */ 
    public static long TOR_CONNECT_TIMEOUT_MILLIS = 180L*1000L;
    /** to access servers via Tor:  max. connection timeout: 120 minutes */
    public static long TOR_OVERALL_TIMEOUT_MILLIS = 120L*60L*1000L;
    /** to access servers via Tor: max. bytes to transfer (to avoid endless transfers and out-of-memory problems): 50 MByte */ 
    public static long TOR_MAX_FILETRANSFER_BYTES = 50L*1024L*1024L;
    /** to access servers via Tor: minimum throughput: 30 KBytes / 60 seconds */ 
    public static long TOR_THROUGPUT_TIMEFRAME_MIN_BYTES = 30L*1024L;
    /** to access servers via Tor: minimum throughput: 30 KBytes / 60 seconds */ 
    public static long TOR_THROUGPUT_TIMEFRAME_MILLIS = 60L*1000L;

    /** QoS-parameter, see updateRanking in Circuit.java */
    public static final int CIRCUIT_ESTABLISHMENT_TIME_IMPACT = 5;

    // Security parameters
    public static int streamsPerCircuit = 50;
    /** see Server.getRefinedRankingIndex */
    public static float rankingIndexEffect = 0.9f;
    /** Path length */
    public static int routeMinLength = 3;
    /** Path length */
    public static int routeMaxLength = 3;
    
    /** Don't establish any circuits until a certain part of the descriptors of running routers is present */ 
    public static double minDescriptorsPercentage = 0.1;
    /** Wait at most until this number of descriptors is known */
    public static int minDescriptors = 10*routeMinLength;
    
    /** True if there shouldn't be two class C addresses on the route */
    public static boolean routeUniqueClassC = true;
    /** True if there should be at most one router from one country (or block of countries) on the path */
    public static boolean routeUniqueCountry = true;
    /** Allow a single node to be present in multiple circuits */
    public static int allowModeMultipleCircuits = 3;

    public static HashSet<String> avoidedCountries; 
    /** collection of fingerprints */
    public static HashSet<byte[]> avoidedNodeFingerprints;

    /** Filenames */
    private static final String TOR_CONFIG_FILENAME = "torrc";
    
    /** Path of the resource */
    public static final String TOR_GEOIPCITY_PATH = "/com/maxmind/geoip/GeoIP.dat";
    public static final int TOR_GEOIPCITY_MAX_FILE_SIZE = 2000000;

    private static String filename;

    /** directory and Co. config */
    public static final int MIN_NUMBER_OF_ROUTERS_IN_CONSENSUS = 50;
    /** the time span that a router description is valid (starting from its publishing time) */
    public static final long ROUTER_DESCRIPTION_VALID_PERIOD_MS = 1L*24L*60L*60L*1000L;

    static {
        try {
            // overwrite defaults if proper system properties are set
            minimumIdleCircuits = getSystemProperty(TOR_SYSTEMPROPERTY_torMinimumIdleCircuits, minimumIdleCircuits);
            maxAllowedSetupDurationMs = getSystemProperty(TOR_SYSTEMPROPERTY_torMaxAllowedSetupDurationMs, (int)maxAllowedSetupDurationMs);
        } catch (Exception e) {
            log.log(Level.SEVERE, "config coulfd not be loaded", e);
        }
    }
    
    /**
     * Read a system property as integer.
     * 
     * @param key
     * @param defaultValue
     * @return the system property as integer;
     *         defaultValue is the system property is not set or not parsable
     */
    final static int getSystemProperty(String key, int defaultValue) {
        String value = System.getProperty(key);
        if (value==null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (Exception e) {
            // value could not be parsed
            return defaultValue;
        }
    }
    
    /**
     * @param readFileName set to false to avoid any access to the lcoal file system
     */
    public TorConfig(boolean readFileName) {
        if (readFileName) 
            init(getConfigDir() + TOR_CONFIG_FILENAME);
        else
            init(null);
    }

    public TorConfig(String filename) {
        init(filename);
    }

    public void reload() {
        if (filename == null) {
            return;
        }
        log.info("TorConfig.reload: reloading config-file "+filename);
        init(filename);
    }

    private void init(String filename) {
        // init set of avoided nodes, countries
        avoidedCountries = new HashSet<String>();
        avoidedNodeFingerprints = new HashSet<byte[]>();
        // read everything else from config
        readFromConfig(filename);
        // set filename, such that file can be reloaded
        TorConfig.filename = filename;
    }

    public void close() {
        writeToFile("/tmp/torrc.test");
    }


    private String replaceSpaceWithSpaceRegExp(String regexp) {
      return regexp.replaceAll(" ","\\\\s+");
    }
    private int parseInt(String config,String name,int myDefault) {
      int x = Integer.parseInt(Parsing.parseStringByRE(config,
              Parsing.compileRegexPattern("^\\s*"+replaceSpaceWithSpaceRegExp(name)+"\\s+(\\d+)"),
              Integer.toString(myDefault)));
      log.finer("TorConfig.parseInt: Parsed '"+name+"' as '"+x+"'");
      return x;
    }
    private String writeInt(String name,int value) {
      return name + " " + value + "\n";
    }
    /*private float parseFloat(String config,String name,float myDefault) {
      float x = Float.parseFloat(Parsing.parseStringByRE(config,"^\\s*"+replaceSpaceWithSpaceRegExp(name)+"\\s+([0-9.]+)",Float.toString(myDefault)));
      log.finer("TorConfig.parseFloat: Parsed '"+name+"' as '"+x+"'");
      return x;
    }*/
    private String writeFloat(String name,float value) {
      return name + " " + value + "\n";
    }
    private String writeDouble(String name,double value) {
        return name + " " + value + "\n";
    }
    private float parseFloat(String config,String name,float myDefault,float lower,float upper) {
      float x = Float.parseFloat(Parsing.parseStringByRE(config,
              Parsing.compileRegexPattern("^\\s*"+replaceSpaceWithSpaceRegExp(name)+"\\s+([0-9.]+)"),
              Float.toString(myDefault)));
      if (x<lower) x = lower;
      if (x>upper) x = upper;
      log.finer("TorConfig.parseFloat: Parsed '"+name+"' as '"+x+"'");
      return x;
    }
    private double parseDouble(String config,String name,double myDefault,double lower,double upper) {
        double x = Double.parseDouble(Parsing.parseStringByRE(config,
                Parsing.compileRegexPattern("^\\s*"+replaceSpaceWithSpaceRegExp(name)+"\\s+([0-9.]+)"),
                Double.toString(myDefault)));
        if (x<lower) x = lower;
        if (x>upper) x = upper;
        log.finer("TorConfig.parseDouble: Parsed '"+name+"' as '"+x+"'");
        return x;
      }
    private String parseString(String config,String name,String myDefault) {
      String x = Parsing.parseStringByRE(config,
              Parsing.compileRegexPattern("^\\s*"+replaceSpaceWithSpaceRegExp(name)+"\\s+(\\S.*?)$"),
              myDefault);
      log.finer("TorConfig.parseString: Parsed '"+name+"' as '"+x+"'");
      return x;
    }
    private String writeString(String name, String value) {
      return name + " " + value + "\n"; 
    }
    private boolean parseBoolean(String config,String name,boolean myDefault) {
      String mydef = "false";
      if (myDefault) mydef="true";
      String x = Parsing.parseStringByRE(config,
              Parsing.compileRegexPattern("^\\s*"+replaceSpaceWithSpaceRegExp(name)+"\\s+(\\S.*?)$"),
              mydef).trim();
      boolean ret = false;
      if (x.equals("1") || x.equalsIgnoreCase("true") || x.equalsIgnoreCase("yes")) ret = true;
      log.finer("TorConfig.parseBoolean: Parsed '"+name+"' as '"+ret+"'");
      return ret;
    }
    private String writeBoolean(String name, boolean value) {
      if (value == true) {
        return name + " " + "true" + "\n";
      } else {
        return name + " " + "false" + "\n";
      }
    }
    private void readFromConfig(String filename) {
        try {
            String config="";
            if (filename != null) {
                DataInputStream sin = new DataInputStream(new FileInputStream(new File(filename)));
                //DataInputStream sin = new DataInputStream(ClassLoader.getSystemResourceAsStream(filename));
                config = readAllFromStream(sin);
                log.finer( "TorConfig.readFromConfig(): " + config);
            }
            //  Read variable config information here

            // security parameters
            streamsPerCircuit= parseInt(config,"StreamsPerCircuit",streamsPerCircuit);
            rankingIndexEffect = parseFloat(config,"RankingIndexEffect",rankingIndexEffect,0,1);
            routeMinLength = parseInt(config,"RouteMinLength",routeMinLength);
            routeMaxLength = parseInt(config,"RouteMaxLength",routeMaxLength);            
            minDescriptorsPercentage = parseDouble(config,"MinPercentage",minDescriptorsPercentage,0,1);
            minDescriptors = parseInt(config,"MinDescriptors",minDescriptors);
            routeUniqueClassC = parseBoolean(config,"RouteUniqClassC",routeUniqueClassC);
            routeUniqueCountry = parseBoolean(config,"RouteUniqCountry",routeUniqueCountry);
            allowModeMultipleCircuits = parseInt(config,"AllowNodeMultipleCircuits", allowModeMultipleCircuits);
            // Avoid Countries
            Pattern p = Pattern.compile("^\\s*AvoidCountry\\s+(.*?)$", Pattern.MULTILINE + Pattern.CASE_INSENSITIVE + Pattern.UNIX_LINES);
            Matcher m = p.matcher(config);
            while(m.find()) {
              log.fine("TorConfig.readConfig: will avoid country: "+m.group(1));
              avoidedCountries.add(m.group(1));
            }
            // Avoid Nodes
            p = Pattern.compile("^\\s*AvoidNode\\s+(.*?)$", Pattern.MULTILINE + Pattern.CASE_INSENSITIVE + Pattern.UNIX_LINES);
            m = p.matcher(config);
            while(m.find()) {
                log.fine("TorConfig.readConfig: will avoid node: "+m.group(1));
                avoidedNodeFingerprints.add(Encoding.parseHex(m.group(1)));
            }
            // functionality 
            cacheMaxAgeSeconds = parseInt(config,"cacheMaxAgeSeconds",cacheMaxAgeSeconds);
            startupDelaySeconds = parseInt(config,"startupDelaySeconds",startupDelaySeconds);

            dirserverPort = parseInt(config,"dirserverport",0);
            orPort = parseInt(config,"orport",0);
            nickname = parseString(config,"nickname",nickname);
            // QoS parameters
            retriesConnect = parseInt(config,"RetriesConnect",retriesConnect);
            retriesStreamBuildup = parseInt(config,"RetriesStreamBuildup",retriesStreamBuildup);
            reconnectCircuit = parseInt(config,"ReconnectCircuit",reconnectCircuit);
            defaultIdleCircuits = parseInt(config,"DefaultIdleCircuits",defaultIdleCircuits);

            queueTimeoutCircuit = parseInt(config,"QueueTimeoutCircuit",queueTimeoutCircuit);
            queueTimeoutResolve = parseInt(config,"QueueTimeoutResolve",queueTimeoutResolve);
            queueTimeoutStreamBuildup = parseInt(config,"QueueTimeoutStreamBuildup",queueTimeoutStreamBuildup);

            rankingTransferPerServerUpdate = parseFloat(config,"RankingTransferPerServerUpdate",rankingTransferPerServerUpdate,0,1);

            circuitClosesOnFailures = parseInt(config,"CircuitClosesOnFailures",circuitClosesOnFailures);
            circuitsMaximumNumber = parseInt(config,"circuitsMaximumNumber",circuitsMaximumNumber);

            veryAggressiveStreamBuilding = parseBoolean(config,"veryAggressiveStreamBuilding",veryAggressiveStreamBuilding);
            // directory parameters
            intervalDirectoryV1Refresh = parseInt(config,"DirectoryV1Refresh",intervalDirectoryV1Refresh);
            intervalDirectoryRefresh   = parseInt(config,"DirectoryRefresh",intervalDirectoryRefresh);
            dirV2ReadMaxNumberOfDescriptorsFirstTime = parseInt(config,"MaxNumberOfDescriptorsFirstTime",dirV2ReadMaxNumberOfDescriptorsFirstTime);
            dirV2ReadMaxNumberOfDescriptorsPerUpdate = parseInt(config,"MaxNumberOfDescriptorsPerUpdate",dirV2ReadMaxNumberOfDescriptorsPerUpdate);
            dirV2ReloadRetries = parseInt(config,"dirV2ReloadRetries",dirV2ReloadRetries);
            dirV2ReloadTimeout = parseInt(config,"dirV2ReloadTimeout",dirV2ReloadTimeout);
            dirV2DescriptorsPerBatch  = parseInt(config,"dirV2DescriptorsPerBatch",dirV2DescriptorsPerBatch);
        } catch (IOException e) {
            log.warning("TorConfig.readFromConfig(): Warning: " + e.getMessage());
        }
    }

    /**
     * reads all data from an inputstream
     */
    private static String readAllFromStream(InputStream in) {
        // DataInputStream.readLine() is depreciated
        BufferedReader sin = new BufferedReader(new InputStreamReader(in));
        
        StringBuffer buf = new StringBuffer();
        try {
            String str = sin.readLine();
            while (str != null) {
                buf.append(str);
                buf.append("\n");
                str = sin.readLine();
            }

        } catch (IOException e) {
            /* eof, reset, ... */
        }
        return buf.toString();
    }

    
    /** used to store some new values to a file */
    private void writeToFile(String filename) {
        if (filename==null) {
            return;
        }
        
        try {
            StringBuffer config = new StringBuffer();

            log.fine( "TorConfig.writeToFile(): " + config);
            // Write variable config information here

            // security parameters
            config.append(writeInt("StreamsPerCircuit",streamsPerCircuit));
            config.append(writeFloat("RankingIndexEffect",rankingIndexEffect));
            config.append(writeInt("RouteMinLength",routeMinLength));
            config.append(writeInt("RouteMaxLength",routeMaxLength));
            config.append(writeDouble("MinPercentage",minDescriptorsPercentage));
            config.append(writeInt("MinDescriptors",minDescriptors));
            config.append(writeBoolean("RouteUniqClassC",routeUniqueClassC));
            config.append(writeBoolean("RouteUniqCountry",routeUniqueCountry));
            config.append(writeInt("AllowNodeMultipleCircuits", allowModeMultipleCircuits));

             // Avoided countries
            Iterator<String> it = avoidedCountries.iterator();
            while (it.hasNext()) {
                String countryName = (String)it.next();
                config.append(writeString("AvoidCountry",countryName)); 
                log.fine("TorConfig.writeToFile: will avoid country "+countryName);
            }
             // Avoided nodes
            for (byte[] fingerprint : avoidedNodeFingerprints) {
                String fingerprintStr = Encoding.toHexString(fingerprint);
                config.append(writeString("AvoidNode", fingerprintStr)); 
                log.fine("TorConfig.writeToFile: will avoid node "+fingerprintStr);
            }
            // Functionality 
            config.append(writeInt("cacheMaxAgeSeconds",cacheMaxAgeSeconds));
            config.append(writeInt("startupDelaySeconds",startupDelaySeconds));
            config.append(writeInt("dirserverport",dirserverPort));
            config.append(writeInt("orport",orPort));
            config.append(writeString("nickname",nickname));

            // QoS parameters
            config.append(writeInt("RetriesConnect",retriesConnect));
            config.append(writeInt("RetriesStreamBuildup",retriesStreamBuildup));
            config.append(writeInt("ReconnectCircuit",reconnectCircuit));
            config.append(writeInt("DefaultIdleCircuits",defaultIdleCircuits));

            config.append(writeInt("QueueTimeoutCircuit",queueTimeoutCircuit));
            config.append(writeInt("QueueTimeoutResolve",queueTimeoutResolve));
            config.append(writeInt("QueueTimeoutStreamBuildup",queueTimeoutStreamBuildup));

            config.append(writeInt("CircuitClosesOnFailures",circuitClosesOnFailures));
            config.append(writeInt("circuitsMaximumNumber",circuitsMaximumNumber));
            
            config.append(writeBoolean("veryAggressiveStreamBuilding",veryAggressiveStreamBuilding));

            // FIXME: Check if this really works
            config.append(writeFloat("RankingTransferPerServerUpdate",rankingTransferPerServerUpdate));
            // directory parameters
            config.append(writeInt("DirectoryV1Refresh",intervalDirectoryV1Refresh));
            config.append(writeInt("DirectoryRefresh",intervalDirectoryRefresh));
            config.append(writeInt("MaxNumberOfDescriptorsFirstTime",dirV2ReadMaxNumberOfDescriptorsFirstTime));
            config.append(writeInt("MaxNumberOfDescriptorsPerUpdate",dirV2ReadMaxNumberOfDescriptorsPerUpdate));
            config.append(writeInt("dirV2ReloadRetries",dirV2ReloadRetries));
            config.append(writeInt("dirV2ReloadTimeout",dirV2ReloadTimeout));
            config.append(writeInt("dirV2DescriptorsPerBatch",dirV2DescriptorsPerBatch));

            FileWriter writer = new FileWriter(new File(filename));
            writer.write(config.toString());
            writer.close();

        } catch (IOException e) {
            log.warning("TorConfig.writeToFile(): Warning: " + e.getMessage());
        }
 
    }

    private static String getConfigDir() {
        String os = operatingSystem();
        if (os.equals("Linux"))
            return System.getProperty("user.home")
                    + System.getProperty("file.separator") + ".TorJava"
                    + System.getProperty("file.separator");
        return System.getProperty("user.home")
                + System.getProperty("file.separator") + "TorJava"
                + System.getProperty("file.separator");
    }

    public static String operatingSystem() {
        return System.getProperty("os.name");
    }
}

