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

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.silvertunnel.netlib.layer.tor.api.Fingerprint;
import org.silvertunnel.netlib.layer.tor.common.TorConfig;
import org.silvertunnel.netlib.layer.tor.util.Encoding;
import org.silvertunnel.netlib.layer.tor.util.Encryption;
import org.silvertunnel.netlib.layer.tor.util.Parsing;
import org.silvertunnel.netlib.layer.tor.util.TorException;
import org.silvertunnel.netlib.layer.tor.util.Util;


/**
 * An object of this class stores a parsed
 * directory protocol V3 network-status consensus document
 * of Tor.
 * 
 * @author hapke
 */
public class DirectoryConsensus {
    public static final Logger log = Logger.getLogger(DirectoryConsensus.class.getName());
    
    private Date validAfter;
    private Date freshUntil;
    private Date validUntil;
    
    private Map<Fingerprint,RouterStatusDescription> fingerprintsNetworkStatusDescriptors = new HashMap<Fingerprint,RouterStatusDescription>();
    
    private static final Pattern VERSION_PATTERN = Parsing.compileRegexPattern("^network-status-version (\\d+)");
    private static final Pattern SIGNEDDATA_PATTERN = Parsing.compileRegexPattern("^(network-status-version.*?directory-signature )");

    
    /**
     * Parse a directory protocol V3 network-status consensus document
     * 
     * @param consensusStr                document received form directory server
     * @param authorityKeyCertificates    all authority signing certificates - needed to check the consensus document
     * @param currentDate                 current dae and time - needed to check the consensus document
     * @throws Exception if the consensus is invalid (e.g. empty or invalid signatures or outdated)
     */
    public DirectoryConsensus (String consensusStr, AuthorityKeyCertificates authorityKeyCertificates, Date currentDate)
    throws TorException, ParseException {
        
        // Check the version
        String version = Parsing.parseStringByRE(consensusStr, VERSION_PATTERN, "");
        if (!version.equals("3")) throw new TorException("wrong network status version");

        // parse and check valid-after, fresh-until, valid-until
        setValidAfter(Parsing.parseTimestampLine("valid-after", consensusStr));
        setFreshUntil(Parsing.parseTimestampLine("fresh-until", consensusStr));
        setValidUntil(Parsing.parseTimestampLine("valid-until", consensusStr));
        log.info("Directory.parseDirV3NetworkStatus: Consensus document validAfter="+getValidAfter()+", freshUntil="+getFreshUntil()+", validUntil="+getValidUntil());
        if (!isValidDate(currentDate)) {
            throw new TorException("invalid validAfter="+getValidAfter()+", freshUntil="+getFreshUntil()+" or and validUntil="+getValidUntil()+" for currentDate="+currentDate);
        }
        
        byte[] signedData = Parsing.parseStringByRE(consensusStr, SIGNEDDATA_PATTERN, "").getBytes();
        log.info("consensus: extracted signed data (length)="+signedData.length);      
        
        // Parse signatures
        Pattern pSignature = Pattern.compile("^directory-signature (\\S+) (\\S+)\\s*\n-----BEGIN SIGNATURE-----\n(.*?)-----END SIGNATURE",
                Pattern.UNIX_LINES + Pattern.MULTILINE + Pattern.CASE_INSENSITIVE + Pattern.DOTALL);
        Matcher mSig = pSignature.matcher(consensusStr);
        Set<Fingerprint> dirIdentityKeyDigestOfMatchingSignatures = new HashSet<Fingerprint>();
        while (mSig.find()) {
            byte[] identityKeyDigest = Encoding.parseHex(mSig.group(1));
            byte[] signingKeyDigest = Encoding.parseHex(mSig.group(2));
            byte[] signature = Encoding.parseBase64(mSig.group(3));
            if (log.isLoggable(Level.FINE)) {
                log.fine("Directory.parseDirV3NetworkStatus: Extracted identityKeyDigest(hex)="+Encoding.toHexString(identityKeyDigest));
                log.info("Directory.parseDirV3NetworkStatus: Extracted signingKeyDigest(hex)="+Encoding.toHexString(signingKeyDigest));
                log.info("Directory.parseDirV3NetworkStatus: Found signature(base64)="+Encoding.toBase64(signature));
            }
            
            // verify signature
            AuthorityKeyCertificate authorityKeyCertificate = authorityKeyCertificates.getCertByFingerprints(
                    new FingerprintImpl(identityKeyDigest), new FingerprintImpl(signingKeyDigest));
            if (authorityKeyCertificate==null) {
                log.fine("No authorityKeyCertificate found");
                continue;
            }
            if (log.isLoggable(Level.FINE)) {
                log.fine("authorityKeyCertificate signingKeyDigest(hex)="+Encoding.toHexString(authorityKeyCertificate.getDirSigningKeyDigest().getBytes()));
            }
            if (signature.length < 1) {
                log.fine("No signature found in network status");
                continue;
            }
            if (!Encryption.verifySignature(signature, authorityKeyCertificate.getDirSigningKey(), signedData)) {
                log.fine("Directory signature verification failed for identityKeyDigest(hex)="+Encoding.toHexString(identityKeyDigest));
                continue;
            }
            // verification successful for this signature
            dirIdentityKeyDigestOfMatchingSignatures.add(authorityKeyCertificate.getDirIdentityKeyDigest());
            log.info("single signature verification ok for identityKeyDigest(hex)="+Encoding.toHexString(identityKeyDigest));
        }
        final int CONSENSUS_MIN_VALID_SIGNATURES = 4;
        int sigNum = dirIdentityKeyDigestOfMatchingSignatures.size(); 
        if (sigNum<CONSENSUS_MIN_VALID_SIGNATURES) {
            throw new TorException("Directory signature verification failed: only "+sigNum+" (different) signatures found");
        }
        log.info("signature verification accepted");
      
        // Parse the single routers
        Pattern pRouter = Pattern.compile("^r (\\S+) (\\S+) (\\S+) (\\S+) (\\S+) (\\S+) (\\d+) (\\d+)\\s*\ns ([a-z0-9 ]+)?", 
                Pattern.UNIX_LINES + Pattern.MULTILINE + Pattern.CASE_INSENSITIVE + Pattern.DOTALL);
        Matcher m = pRouter.matcher(consensusStr);      
        // Loop to extract all routers
        while (m.find()) {
            RouterStatusDescription sinfo = new RouterStatusDescription();
            sinfo.setNickname(m.group(1));
            Fingerprint fingerprint = new FingerprintImpl(Encoding.parseBase64(m.group(2))); 
            sinfo.setFingerprint(fingerprint);
            sinfo.setDigestDescriptor(Encoding.parseBase64(m.group(3)));
            sinfo.setLastPublication(Util.parseUtcTimestamp(m.group(4)+" "+m.group(5)));
            sinfo.setIp(m.group(6));
            sinfo.setOrPort(Integer.parseInt(m.group(7)));
            sinfo.setDirPort(Integer.parseInt(m.group(8)));
            sinfo.setFlags(m.group(9));
            if (sinfo.getFlags().contains("Running")) {
                getFingerprintsNetworkStatusDescriptors().put(fingerprint, sinfo);
            }
        }
    }    

    /**
     * Check the timestamps.
     * Check that at least MIN_NUMBER_OF_ROUTERS are contained.
     *  
     * @param now    the current time 
     * @return true=valid; false otherwise
     */
    public boolean isValid(Date now) {
        // check time stamps
        if (!isValidDate(now)) {
            return false;
        }
        
        // check number of routers
        if (fingerprintsNetworkStatusDescriptors.size()<TorConfig.MIN_NUMBER_OF_ROUTERS_IN_CONSENSUS) {
            // too few
            log.warning("too few number of routers="+fingerprintsNetworkStatusDescriptors.size());
            return false;
        }

        // everything is fine
        return true;
    }

    /**
     * Check the timestamps.
     * 
     * Final because called from inside the constructor.
     *  
     * @param now    the current time 
     * @return true=valid; false otherwise
     */
    private final boolean isValidDate(Date now) {
        // check time stamps
        if (validAfter==null || validAfter.after(now)) {
            // too new
            log.warning("validAfter="+validAfter+" is too new  for currentDate="+now+" - this should never occur with consistent data");
            return false;
        }
        if (freshUntil==null /*|| freshUntil.before(currentDate)*/) {
            log.info("freshUntil="+freshUntil+" is invalid for currentDate="+now);
        }
        if (validUntil==null || validUntil.before(now)) {
            // too old
            log.info("validUntil="+validUntil+" is too old for currentDate="+now);
            return false;
        }
        
        // everything is fine
        return true;
    }

    /**
     * @param now    the current time 
     * @return true if a refresh should happen now
     */
    public boolean needsToBeRefreshed(Date now) {
        if (validUntil.before(now)) {
            // too old
            log.warning("must be refrehed - but it is actually to late; validUntil="+validUntil);
            return true;
        }
        
        // TODO: this algorithm must be improved based on the spec to prevent dir server from damage
        if (freshUntil.before(now)) {
            // should be refreshed soon
            //TODO: return true;
        }

        // default check
        return !isValid(now);
    }

    ///////////////////////////////////////////////////////
    // generated getters and setters
    ///////////////////////////////////////////////////////

    public Date getValidAfter() {
        return validAfter;
    }

    public void setValidAfter(Date validAfter) {
        this.validAfter = validAfter;
    }

    public Date getFreshUntil() {
        return freshUntil;
    }

    public void setFreshUntil(Date freshUntil) {
        this.freshUntil = freshUntil;
    }

    public Date getValidUntil() {
        return validUntil;
    }

    public void setValidUntil(Date validUntil) {
        this.validUntil = validUntil;
    }

    public Map<Fingerprint, RouterStatusDescription> getFingerprintsNetworkStatusDescriptors() {
        return fingerprintsNetworkStatusDescriptors;
    }

    public void setFingerprintsNetworkStatusDescriptors(
            Map<Fingerprint, RouterStatusDescription> fingerprintsNetworkStatusDescriptors) {
        this.fingerprintsNetworkStatusDescriptors = fingerprintsNetworkStatusDescriptors;
    }
}
