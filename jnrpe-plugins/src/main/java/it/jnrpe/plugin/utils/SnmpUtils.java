/*
 * Copyright (c) 2014 Massimiliano Ziccardi
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.jnrpe.plugin.utils;

import java.io.IOException;

import org.snmp4j.AbstractTarget;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

/**
 * Snmp utility class
 * 
 * @author Frederico Campos
 * 
 */
public class SnmpUtils {

	public static String snmpGet(String host, int port, String community,
			String strOID, String mibs, boolean useNext, int timeout,
			int retries, String username, String password, String authType)
			throws Exception {
		String strResponse = null;
		ResponseEvent response;
		Snmp snmp = null;
		TransportMapping transport = null;
		try {
			OctetString comm = null;
			if (community != null) {
				comm = new OctetString(community);
			}
			host = host + "/" + port;
			Address tHost = new UdpAddress(host);
			AbstractTarget target = getTarget(tHost, comm, retries, timeout);
			PDU pdu = new PDU();
			String[] oids = strOID.split(",");
			for (String oid : oids) {
				pdu.add(new VariableBinding(new OID(oid)));
			}
			if (useNext) {
				pdu.setType(PDU.GETNEXT);
			} else {
				pdu.setType(PDU.GET);
			}
			transport = new DefaultUdpTransportMapping();
			transport.listen();
			snmp = getSnmp(username, password, authType, transport);
			response = snmp.get(pdu, target);
			if (response != null) {
				if (response.getResponse().getErrorStatusText()
						.equalsIgnoreCase("Success")) {
					PDU pduresponse = response.getResponse();
					strResponse = pduresponse.getVariableBindings()
							.firstElement().toString();
					if (strResponse.contains("=")) {
						String str = strResponse;
						int len = str.indexOf("=");
						strResponse = str.substring(len + 1, str.length());
					}
				}
			} else {
				throw new Exception(response.getResponse().getErrorStatusText());
			}

		} catch (Exception e) {
			throw new Exception(e);
		} finally {
			if (transport != null) {
				transport.close();
			}
			if (snmp != null) {
				snmp.close();
			}
		}
		System.out.println("[" + strResponse + "]");
		return strResponse;
	}

	private static AbstractTarget getTarget(Address tHost, OctetString comm,
			int retries, int timeout) {
		CommunityTarget comtarget = null;
		if (comm != null) {
			comtarget = new CommunityTarget();
			comtarget.setCommunity(comm);
			comtarget.setVersion(SnmpConstants.version1);
			comtarget.setAddress(tHost);
			comtarget.setRetries(retries);
			comtarget.setTimeout(timeout * 1000);
		}
		return comtarget;
	}

	private static Snmp getSnmp(String username, String password,
			String authType, TransportMapping transport) throws IOException {
		Snmp snmp = null;
		if (username != null && password != null && authType != null) {
			USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(
					MPv3.createLocalEngineID()), 0);
			SecurityModels.getInstance().addSecurityModel(usm);
			snmp = new Snmp(new DefaultUdpTransportMapping());
			OID auth = null;
			if (authType.equals("md5")) {
				auth = AuthMD5.ID;
			} else if (authType.equals("des")) {
				auth = AuthSHA.ID;
			}
			snmp.getUSM().addUser(
					new OctetString(username),
					new UsmUser(new OctetString(username), auth,
							new OctetString(password), auth, null));
		} else {
			snmp = new Snmp(transport);
		}
		return snmp;
	}

}
