package pso.tomcat_security_valve;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

public class Configuration {
	private boolean validateHostName;
	private Set<String> validHosts = new HashSet<>();
	private Set<String> skipValveForHostNames = new HashSet<>();
	private Set<String> skipValveForRemoteIps = new HashSet<>();
	
	private boolean allowOnlySecureConnections;
	private boolean redirectInsecureGETRequests;
	private boolean enableSTS;
	private String sTSParameters;
	
	private boolean debug;
	private boolean enableReloadConfig;
	private String reloadConfigUrl;

	private boolean enableIpRestrictionPerContext;
	private Map<String, Set<String>> ipRestrictionContext = new HashMap<>();

	private ArrayList<String> skipValveForContexts = new ArrayList<>();
	
	private String invalidHostNameMessage="Invalid host name.";
	private String onlySecurityConnectionsAllowedMessage="Only secure connections are allowed. Please use https.";

	public static Configuration getConfiguration(String fileName) {
		File f=new File(fileName);
		if (!f.exists() || f.isDirectory()) {
			throw new RuntimeException("pso-tomcat-security-valve: config file does not exist "+fileName);
		}
		Configuration c=new Configuration();
		Properties prop = new Properties();
		InputStream input = null;
		try {
			input = new FileInputStream(f);
			prop.load(input);
			c.validateHostName="true".equals(prop.getProperty("validateHostName"));
			c.debug="true".equals(prop.getProperty("debug"));
			c.allowOnlySecureConnections="true".equals(prop.getProperty("allowOnlySecureConnections"));
			c.redirectInsecureGETRequests="true".equals(prop.getProperty("redirectInsecureGETRequests"));
			c.enableIpRestrictionPerContext="true".equals(prop.getProperty("enableIpRestrictionPerContext"));
			c.enableReloadConfig="true".equals(prop.getProperty("enableReloadConfig"));
			c.enableSTS="true".equals(prop.getProperty("enableSTS"));
			c.sTSParameters=prop.getProperty("STSParameters");
			if (c.sTSParameters==null) c.sTSParameters="max-age=31536000; includeSubDomains; preload";

			for (int i=0;i<=99;i++) {
				String host=prop.getProperty("validHost_"+(i<10?("0"+i):i));
				if (host==null || host.trim().length()==0) continue;
				c.validHosts.add(host.trim());
			}

			for (int i=0;i<=99;i++) {
				String ip=prop.getProperty("skipValveForRemoteIp_"+(i<10?("0"+i):i));
				if (ip==null || ip.trim().length()==0) continue;
				c.skipValveForRemoteIps.add(ip.trim());
			}
			
			for (int i=0;i<=99;i++) {
				String skipHostName=prop.getProperty("skipValveForHostName_"+(i<10?("0"+i):i));
				if (skipHostName==null || skipHostName.trim().length()==0) continue;
				c.skipValveForHostNames.add(skipHostName);
			}
			
			for (int i=0;i<=99;i++) {
				String skipContext=prop.getProperty("skipValveForContext_"+(i<10?("0"+i):i));
				if (skipContext==null || skipContext.trim().length()==0) continue;
				c.skipValveForContexts.add(skipContext.trim());
			}

			c.reloadConfigUrl=prop.getProperty("reloadConfigUrl");
			if (c.reloadConfigUrl!=null) c.reloadConfigUrl=c.reloadConfigUrl.trim();
			c.enableReloadConfig=c.enableReloadConfig && (c.reloadConfigUrl!=null || !c.reloadConfigUrl.isEmpty());

			for (int i=0;i<=99;i++) {
				String restrictionContext=prop.getProperty("ipRestrictionContext_"+(i<10?("0"+i):i));
				if (restrictionContext==null || restrictionContext.trim().length()==0) continue;

				HashSet<String> ipSet=new HashSet<>();
				c.ipRestrictionContext.put(restrictionContext, ipSet);
				String ipStr=prop.getProperty("ipRestrictionContext."+restrictionContext);
				if (ipStr==null || ipStr.length()==0) continue;
				String[] ips=ipStr.split(";");
				for (int j=0;j<ips.length;j++) {
					String ip=ips[j].trim();
					if (!ip.isEmpty()) ipSet.add(ip);
				}
			}
			if (prop.getProperty("invalidHostNameMessage")!=null) 
				c.invalidHostNameMessage=prop.getProperty("invalidHostNameMessage");
			if (prop.getProperty("onlySecurityConnectionsAllowedMessage")!=null) 
				c.onlySecurityConnectionsAllowedMessage=prop.getProperty("onlySecurityConnectionsAllowedMessage");
			

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException("pso-tomcat-security-valve: Error loading config file "+ex.getMessage(), ex);
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

	public boolean isValidateHostName() {
		return validateHostName;
	}

	public Set<String> getValidHosts() {
		return validHosts;
	}

	public boolean isAllowOnlySecureConnections() {
		return allowOnlySecureConnections;
	}

	public Set<String> getSkipValveForRemoteIps() {
		return skipValveForRemoteIps;
	}

	public boolean isRedirectInsecureGETRequests() {
		return redirectInsecureGETRequests;
	}

	public boolean isDebug() {
		return debug;
	}

	public boolean isEnableReloadConfig() {
		return enableReloadConfig;
	}
	
	public String getReloadConfigUrl() {
		return reloadConfigUrl;
	}

	public boolean isEnableIpRestrictionPerContext() {
		return enableIpRestrictionPerContext;
	}

	public Map<String, Set<String>> getIpRestrictionContext() {
		return ipRestrictionContext;
	}

	public List<String> getSkipValveForContexts() {
		return skipValveForContexts;
	}

	public Set<String> getSkipValveForHostNames() {
		return skipValveForHostNames;
	}

	public String getInvalidHostNameMessage() {
		return invalidHostNameMessage;
	}

	public String getOnlySecurityConnectionsAllowedMessage() {
		return onlySecurityConnectionsAllowedMessage;
	}

	public boolean isEnableSTS() {
		return enableSTS;
	}

	public String getSTSParameters() {
		return sTSParameters;
	}

}
