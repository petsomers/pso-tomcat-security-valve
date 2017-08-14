package pso.tomcat_security_valve;

import static org.junit.Assert.*;

import org.junit.Test;

public class ConfigurationTest {

	@Test
	public void testConfigurationLoader() {
		Configuration conf=Configuration.getConfiguration("src/test/resources/config_example1.properties");
		assertTrue(conf.isEnableReloadConfig());
		assertEquals("/reload_security_valve_config", conf.getReloadConfigUrl());
		assertEquals(2, conf.getSkipValveForHostNames().size());
		assertTrue(conf.getSkipValveForHostNames().contains("localhost"));
		assertTrue(conf.getSkipValveForRemoteIps().contains("192.168.1.41"));
		assertTrue(conf.getValidHosts().contains("www.example2.com"));
		assertTrue(conf.isAllowOnlySecureConnections());
		assertTrue(conf.isRedirectInsecureGETRequests());
		assertEquals("max-age=31536000; includeSubDomains; preload", conf.getSTSParameters());
		assertTrue(conf.isEnableSTS());
		assertEquals("/reload_security_valve_config", conf.getReloadConfigUrl());
		assertEquals("Invalid host name.", conf.getInvalidHostNameMessage());
		assertTrue(conf.isEnableIpRestrictedContexts());
		assertTrue(conf.getIpRestrictedContextMap().containsKey("/probe-2.4.0"));
		assertTrue(conf.getIpRestrictedContextMap().get("/probe-2.4.0").contains("192.168.1.2"));
		assertEquals("/probe-2.4.0/admin", conf.getIpRestrictedContexts().get(0));
		assertEquals(conf.getIpRestrictedContextResponseCode(),404);
		assertTrue(conf.getAddHeaderContexts().contains("/iframe_context"));
		assertEquals("Content-Security-Policy",conf.getAddHeadersForContext().get("/iframe_context").get(0).getHeader());
	}

}
