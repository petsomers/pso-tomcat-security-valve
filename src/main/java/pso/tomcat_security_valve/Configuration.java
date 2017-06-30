package tomcat_security_valve;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

public class Configuration {
	private Set<String> validHosts = new HashSet<>();
	private Set<String> allowInsecureRemoteIps = new HashSet<>();
	private boolean debug;
	private boolean onlySecureConnections;
	private boolean redirectInsecureGetRequests;
	private String reloadConfigUrl;

	private Map<String, Set<String>> ipRestrictionForContext = new HashMap<>();

	public static Configuration getConfiguration(String fileName) {
		String catalinaBase=System.getenv("catalina.base");
		if (catalinaBase!=null)
			fileName=fileName.replace("{base}", catalinaBase);
		
		Configuration c=new Configuration();
		Properties prop = new Properties();
		InputStream input = null;
		try {
			input = new FileInputStream(fileName);
			prop.load(input);
			String hosts=prop.getProperty("validHosts");
			if (hosts!=null && hosts.trim().length()>0) {
				String[] hostList=hosts.split(";");
				for (String host:hostList) {
					if (host.trim().length()>0) {
						c.validHosts.add(host);
					}
				}
			}
			c.debug="true".equals(prop.getProperty("debug"));
			c.onlySecureConnections="true".equals(prop.getProperty("onlySecureConnections"));
			c.redirectInsecureGetRequests="true".equals(prop.getProperty("redirectInsecureGetRequests"));
			
			String allowInsecureRemoteIpsStr=prop.getProperty("allowInsecureRemoteIps");
			if (allowInsecureRemoteIpsStr!=null && allowInsecureRemoteIpsStr.length()>0) {
				String[] ipList=allowInsecureRemoteIpsStr.split(";");
				for (String ip:ipList) {
					if (ip.trim().length()>0) {
						c.allowInsecureRemoteIps.add(ip.trim());
					}
				}
			}
			c.reloadConfigUrl=prop.getProperty("reloadConfigUrl");
			String ipRestrictionForContextStr=prop.getProperty("ipRestrictionForContext");
			if (ipRestrictionForContextStr!=null && ipRestrictionForContextStr.length()>0) {
				String[] settingList=ipRestrictionForContextStr.split(";");
				for (String setting:settingList) {
					if (setting.trim().length()>0 && setting.contains(":")) {
						String[] settingItem=ipRestrictionForContextStr.split(":");
						
					}
				}
			}
			
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException("Error starting ise-web-security valve "+ex.getMessage(), ex);
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException e) {
				}
			}
		}
		return c;
	}
		
	
}
