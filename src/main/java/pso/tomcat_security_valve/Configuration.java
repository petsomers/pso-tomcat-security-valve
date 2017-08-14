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

import pso.tomcat_security_valve.model.HeaderValue;

public class Configuration {
	private boolean validateHostName;
	private Set<String> validHosts = new HashSet<>();
	private Set<String> skipValveForHostNames = new HashSet<>();
	private Set<String> skipValveForRemoteIps = new HashSet<>();
	private ArrayList<String> skipValveForContexts = new ArrayList<>();
	
	private boolean allowOnlySecureConnections;
	private boolean redirectInsecureGETRequests;
	private boolean enableSTS;
	private String sTSParameters;
	
	private boolean debug;
	private boolean enableReloadConfig;
	private String reloadConfigUrl;

	private boolean enableIpRestrictedContexts;
	private List<String> ipRestrictedContexts=new ArrayList<>();
	private Map<String, Set<String>> ipRestrictedContextMap = new HashMap<>();
	private int ipRestrictedContextResponseCode;

	private List<String> addHeaderContexts=new ArrayList<>();
	private Map<String, List<HeaderValue>> addHeadersForContext = new HashMap<>();
	
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
			c.enableIpRestrictedContexts="true".equals(prop.getProperty("enableIpRestrictedContexts"));
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

			if (c.enableIpRestrictedContexts) {
				for (int i=0;i<=99;i++) {
					String restrictionContext=prop.getProperty("ipRestrictedContext_"+(i<10?("0"+i):i));
					if (restrictionContext==null || restrictionContext.trim().length()==0) continue;
	
					HashSet<String> ipSet=new HashSet<>();
					c.ipRestrictedContextMap.put(restrictionContext, ipSet);
					c.ipRestrictedContexts.add(restrictionContext);
					for (int j=0;j<=99;j++) {
						String ipStr=prop.getProperty("ipRestrictedContext_"+(i<10?("0"+i):i)+"_IP_"+(j<10?("0"+j):j));
						if (ipStr!=null && !ipStr.isEmpty()) {
							ipSet.add(ipStr);
						}
					}
				}
				// sort descending 
				// forces to check deeper contexts prior to higher level contexts.
				c.ipRestrictedContexts.sort((s1,s2) -> s2.compareTo(s1));
				String responseCode=prop.getProperty("ipRestrictedContextResponseCode");
				if (responseCode!=null && !responseCode.isEmpty()) {
					try {
						c.ipRestrictedContextResponseCode=Integer.parseInt(responseCode);
					} catch (NumberFormatException nfe) {
						System.out.println("pso-tomcat-security-valve: invalid number format for ipRestrictionPerContextResponseCode ("+responseCode+"). Using 403 instead.");
						c.ipRestrictedContextResponseCode=403;	
					}
				} else {
					c.ipRestrictedContextResponseCode=403;
				}
			}
			for (int i=0;i<=99;i++) {
				String addHeadersForContext=prop.getProperty("addHeadersForContext_"+(i<10?("0"+i):i));
				if (addHeadersForContext==null || addHeadersForContext.trim().length()==0) continue;
				ArrayList<HeaderValue> headers=new ArrayList<>();
				for (int j=0;j<=99;j++) {
					String header=prop.getProperty("addHeadersForContext_"+(i<10?("0"+i):i)+"_header_"+(j<10?("0"+j):j));
					if (header!=null && header.trim().length()>0) {
						String value=prop.getProperty("addHeadersForContext_"+(i<10?("0"+i):i)+"_value_"+(j<10?("0"+j):j));
						if (value==null) value="";
						headers.add(new HeaderValue(header, value));
					}
				}
				c.addHeaderContexts.add(addHeadersForContext);
				c.addHeadersForContext.put(addHeadersForContext, headers);
			}
			// sort descending 
			// forces to check deeper contexts prior to higher level contexts.
			c.addHeaderContexts.sort((s1,s2) -> s2.compareTo(s1));
			
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

	public boolean isEnableIpRestrictedContexts() {
		return enableIpRestrictedContexts;
	}

	public Map<String, Set<String>> getIpRestrictedContextMap() {
		return ipRestrictedContextMap;
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

	public int getIpRestrictedContextResponseCode() {
		return ipRestrictedContextResponseCode;
	}

	public List<String> getIpRestrictedContexts() {
		return ipRestrictedContexts;
	}

	public Map<String, List<HeaderValue>> getAddHeadersForContext() {
		return addHeadersForContext;
	}

	public List<String> getAddHeaderContexts() {
		return addHeaderContexts;
	}

}
