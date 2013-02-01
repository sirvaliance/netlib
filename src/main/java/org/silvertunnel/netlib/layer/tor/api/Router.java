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

package org.silvertunnel.netlib.layer.tor.api;

import java.net.InetAddress;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Set;

/**
 * a compound data structure that keeps track of the static informations we have
 * about a single Tor server.
 * 
 * @author hapke
 */
public interface Router {
    public String getNickname();
    public String getHostname();
    public InetAddress getAddress();
    public String getCountryCode();
    public int getOrPort();
    public int getSocksPort();
    public int getDirPort();
    public int getBandwidthAvg();
    public int getBandwidthBurst();
    public int getBandwidthObserved();
    public String getPlatform();
    public Date getPublished();
    public Fingerprint getFingerprint();
    public int getUptime();
    public RSAPublicKey getOnionKey();
    public RSAPublicKey getSigningKey();
    public RouterExitPolicy[] getExitpolicy();
    public String getContact();
    public Set<Fingerprint> getFamily();
    public Date getValidUntil();
    public Date getLastUpdate();
    public boolean isDirv2Authority();
    public boolean isDirv2Exit();
    public boolean isDirv2Fast();
    public boolean isDirv2Guard();
    public boolean isDirv2Named();
    public boolean isDirv2Stable();
    public boolean isDirv2Running();
    public boolean isDirv2Valid();
    public boolean isDirv2V2dir();
    public float getRankingIndex();
}
