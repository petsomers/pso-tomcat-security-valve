package pso.tomcat_security_valve;

import static org.junit.Assert.*;

import org.junit.Test;

public class ConfigurationTest {

	@Test
	public void test() {
		Configuration conf=Configuration.getConfiguration("src/test/resources/config_example1.properties");
		System.out.println(conf.getReloadConfigUrl());
	}

}
