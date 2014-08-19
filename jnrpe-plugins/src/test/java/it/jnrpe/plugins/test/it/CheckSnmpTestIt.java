package it.jnrpe.plugins.test.it;

import java.io.IOException;

import it.jnrpe.ReturnValue;
import it.jnrpe.Status;
import it.jnrpe.client.JNRPEClient;
import it.jnrpe.client.JNRPEClientException;
import it.jnrpe.commands.CommandDefinition;
import it.jnrpe.commands.CommandOption;
import it.jnrpe.commands.CommandRepository;
import it.jnrpe.plugin.CheckSnmp;
import it.jnrpe.plugins.PluginDefinition;
import it.jnrpe.plugins.mocks.snmp.MOScalarFactory;
import it.jnrpe.plugins.mocks.snmp.SimpleSnmpAgent;
import it.jnrpe.plugins.mocks.snmp.SimpleSnmpClient;
import it.jnrpe.utils.PluginRepositoryUtil;

import org.snmp4j.smi.OID;
import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

public class CheckSnmpTestIt implements ITConstants{

	private SimpleSnmpAgent agent = null;
	private SimpleSnmpClient client = null;

	// standard in RFC-1213	
	private final static String OID = ".1.3.6.1.2.1.1.1.0"; 
	
    @BeforeTest
    public void setup() {
        PluginDefinition checkSnmp = 
                PluginRepositoryUtil.loadFromPluginAnnotation(CheckSnmp.class);
        ITSetup.getPluginRepository().addPluginDefinition(checkSnmp);

        try {
			agent = new SimpleSnmpAgent("0.0.0.0/2001");
			agent.start();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
       
        if (agent != null) {
	        // Since BaseAgent registers some mibs by default we need to unregister
	        // one before we register our own sysDescr. Normally you would
	        // override that method and register the mibs that you need
	        agent.unregisterManagedObject(agent.getSnmpv2MIB());
	     
	        // Register a system description, use one from you product environment
	        // to test with
	        agent.registerManagedObject(MOScalarFactory.createReadOnly(new OID(OID), "MySystemDescr"));
	        
	            // Setup the client to use our newly started agent
	        client = new SimpleSnmpClient("udp:127.0.0.1/2001");
        }
    }
    
	@Test
	public void checkSnmpOk() throws JNRPEClientException{
		
//		String community = "public";
//		CommandRepository cr = ITSetup.getCommandRepository();
//        cr.addCommandDefinition(new CommandDefinition("CHECK_SNMP_OK",
//                "CHECK_SNMP")
//                .addArgument(new CommandOption("hostname", "$ARG1$"))
//                .addArgument(new CommandOption("port", "$ARG2$"))
//                .addArgument(new CommandOption("oid", "$ARG3$"))
//                
//                );
//        JNRPEClient client = new JNRPEClient(BIND_ADDRESS, JNRPE_PORT, false);
//        client.setTimeout(10000);
//        ReturnValue ret =
//                client.sendCommand("CHECK_SNMP_OK", "127.0.0.1", "2001", OID);
//        Assert.assertEquals(ret.getStatus(), Status.OK, ret.getMessage());
		try {
			Assert.assertEquals("MySystemDescr", client.getAsString(new OID(OID)));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@AfterTest
	public void tearDown(){
		if (agent != null) {
			agent.stop();
		}
		if (client != null){
			try {
				client.stop();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
}
