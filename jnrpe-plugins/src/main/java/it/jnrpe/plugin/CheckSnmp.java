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
package it.jnrpe.plugin;

import it.jnrpe.ICommandLine;
import it.jnrpe.Status;
import it.jnrpe.plugin.utils.SnmpUtils;
import it.jnrpe.plugins.Metric;
import it.jnrpe.plugins.MetricGatheringException;
import it.jnrpe.plugins.PluginBase;
import it.jnrpe.plugins.annotations.Option;
import it.jnrpe.plugins.annotations.Plugin;
import it.jnrpe.plugins.annotations.PluginOptions;
import it.jnrpe.utils.BadThresholdException;
import it.jnrpe.utils.thresholds.ThresholdsEvaluatorBuilder;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Plugin(name = "CHECK_SNMP", description = "Checks")
@PluginOptions({
		@Option(shortName = "H", longName = "hostname", description = "IP or hostname", required = false, hasArgs = true, argName = "hostname", optionalArgs = false, option = "hostname"),
		@Option(shortName = "p", longName = "port", description = "Port number (default 161)", required = false, hasArgs = true, argName = "port", optionalArgs = false, option = "port"),
		@Option(shortName = "o", longName = "oid", description = "Object identifier(s) or SNMP variables to query. Only numerical OIDs accepted.", required = true, hasArgs = true, argName = "oid", optionalArgs = false, option = "oid"),
		@Option(shortName = "C", longName = "community", description = "Optional community string for SNMP communication (default is 'public')", required = false, hasArgs = true, argName = "community", optionalArgs = false, option = "community"),
		@Option(shortName = "t", longName = "timeout", description = "Seconds before connection times out (default: 10)", required = false, hasArgs = true, argName = "timeout", optionalArgs = false, option = "timeout"),
		@Option(shortName = "e", longName = "retries", description = "Number of retries to be used in the requests (default 2)", required = false, hasArgs = true, argName = "retries", optionalArgs = false, option = "retries"),
		
		@Option(shortName = "U", longName = "secname", description = "SNMPv3 username", required = false, hasArgs = true, argName = "secname", optionalArgs = false, option = "secname"),
		@Option(shortName = "A", longName = "authpassword", description = "SNMPv3 authentication password", required = false, hasArgs = true, argName = "authpassword", optionalArgs = false, option = "authpassword"),
		
		@Option(shortName = "s", longName = "string", description = "Return OK state (for that OID) if STRING is an exact match", required = false, hasArgs = true, argName = "string", optionalArgs = false, option = "string"),
		@Option(shortName = "r", longName = "ereg", description = "Return OK state (for that OID) if extended regular expression REGEX matches", required = false, hasArgs = true, argName = "ereg", optionalArgs = false, option = "ereg"),
		@Option(shortName = "R", longName = "eregi", description = "Return OK state (for that OID) if case-insensitive extended REGEX matches", required = false, hasArgs = true, argName = "eregi", optionalArgs = false, option = "eregi"),
		@Option(shortName = "i", longName = "invert-search", description = "Invert search result (CRITICAL if found)", required = false, hasArgs = true, argName = "invert-search", optionalArgs = false, option = "invert-search"),
		@Option(shortName = "w", longName = "warning", description = "Warning value if metric is out of range", required = false, hasArgs = true, argName = "warning", optionalArgs = false, option = "warning"),
		@Option(shortName = "c", longName = "critical", description = "Critical value if metric is out of range", required = false, hasArgs = true, argName = "critical", optionalArgs = false, option = "critical")

})

public class CheckSnmp extends PluginBase {
	
	private String DEFAULT_HOST = "localhost";
	
	private int DEFAULT_PORT = 161;
	
	private String DEFAULT_COMMUNITY = "public";
	
	private String DEFAULT_MIB = "ALL";
	
	private int DEFAULT_TIMEOUT = 10;
	
	private int DEFAULT_RETRIES = 2;
	
	@Override
	protected String getPluginName() {
		return "CheckSnmp";
	}

	protected void configureThresholdEvaluatorBuilder(final ThresholdsEvaluatorBuilder thrb, final ICommandLine cl) throws BadThresholdException {
        if (cl.getOptionValue("string") != null){
        	thrb.withLegacyThreshold("string", "1", null, null);
        }else if (cl.getOptionValue("ereg") != null){
        	thrb.withLegacyThreshold("ereg", "1", null, null);
        }else if (cl.getOptionValue("eregi") != null){
        	thrb.withLegacyThreshold("eregi", "1", null, null);
        }else if (cl.getOptionValue("invert-search") != null){
        	thrb.withLegacyThreshold("invert-search", null, null, "1");
        }
        
        thrb.withLegacyThreshold("response", "1", null, null);
    }
	
	public Collection<Metric> gatherMetrics(final ICommandLine cl)
			throws MetricGatheringException {
		List<Metric> metrics = new ArrayList<Metric>();
		
		String host = cl.getOptionValue("host");
		if (host == null) {
			host = DEFAULT_HOST;
		}
		int port = DEFAULT_PORT;
		if (cl.getOptionValue("port") != null){
			port = Integer.parseInt(cl.getOptionValue("port"));
		}
		log.debug(port +"");
		String oid = cl.getOptionValue("oid");
		if (oid == null) {
			throw new MetricGatheringException("No OID specified", Status.UNKNOWN, null);
		}
		String mibs = null;
		if (cl.getOptionValue("mib") != null){
			mibs = cl.getOptionValue("mib");
		}
		int length = oid.split(".").length;
		if (length == 0 || length < 3){
			mibs = DEFAULT_MIB;
		}
		
		String community = cl.getOptionValue("community");
		if (community == null){
			community = DEFAULT_COMMUNITY;
		}
		
		boolean	next = cl.hasOption("next");
		int timeout = DEFAULT_TIMEOUT;
		if (cl.getOptionValue("timeout") != null) {
			timeout = Integer.parseInt(cl.getOptionValue("timeout"));			
		}
		int retries = DEFAULT_RETRIES;
		if (cl.getOptionValue("retries") != null) {
			timeout = Integer.parseInt(cl.getOptionValue("retries"));			
		}
		String secname = cl.getOptionValue("secname");
		String authpassword = cl.getOptionValue("authpassword");
		String auth = cl.getOptionValue("authproto");
		
		String response = null;
		try {
			response = SnmpUtils.snmpGet(host, port, community, oid, mibs, next, timeout, retries, secname, authpassword, auth);
			if (response != null) {
				metrics.add(new Metric("response",response, new BigDecimal(1), null, null));
				metrics.addAll(analyzeResponse(response, cl));
			}else{
				throw new MetricGatheringException("No response received", Status.CRITICAL, null);
			}
		} catch (Exception e) {
			throw new MetricGatheringException(e.getMessage(), Status.CRITICAL, e);
		}
		
		return metrics;
	}
	
	private List<Metric> analyzeResponse(String response, ICommandLine cl){
		List<Metric> metrics = new ArrayList<Metric>();
		return metrics;
	}

}
