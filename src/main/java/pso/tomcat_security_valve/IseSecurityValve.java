package pso.tomcat_security_valve;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;

public class IseSecurityValve extends ValveBase {
	
	private Configuration c;
	
	public void setConfigFile(String fileName) {
		c=Configuration.getConfiguration(fileName);
	}
	
	@Override
	public void invoke(Request request, Response response) throws IOException, ServletException {
		if (c==null) getNext().invoke(request, response);
		
		HttpServletRequest req=(HttpServletRequest)request;
		HttpServletResponse resp=(HttpServletResponse)response;
		
		String serverName=req.getServerName();
		String requestURI=req.getRequestURI();
		String remoteAddr=req.getRemoteAddr();
		if (serverName.equals("127.0.0.1") || serverName.equals("localhost") || requestURI.equals("/health_monitor/") || allowInsecureRemoteIps.contains(remoteAddr)) {
			getNext().invoke(request, response);
			return;
		}
		
		// only allow valid hosts
		if (!validHosts.contains(serverName)) {
			if (debug) {
				System.out.println("IseSecurityValve INFO: Blocking invalid host name '"+serverName+"'");
			}
			resp.getWriter().print("Invalid host name."); // 200
			// resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Invalid host name."); // 404
			return;
		}
		// only allow secure connections
		if (onlySecureConnections && !req.isSecure()) {
			if (requestURI==null || requestURI.trim().length()==0) {
				requestURI="/";
			}
			if (req.getMethod().equals("GET")) {
				String queryString=req.getQueryString();
				if (queryString!=null && queryString.trim().length()>0) {
					queryString="?"+queryString;
				} else {
					queryString="";
				}
				if (debug) {
					System.out.println("IseSecurityFilter INFO: Redirecting insecure GET request to https://"+serverName+requestURI+queryString);
				}
				// FOR NOW NO STS DUE TO TEST ISSUES 
				resp.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
				resp.sendRedirect("https://"+serverName+requestURI+queryString);
				return;
			} else {
				if (debug) {
					System.out.println("IseSecurityValve INFO: Insecure POST request http://"+serverName+requestURI);
				}
				resp.getWriter().print("Only secure connections are allowed. Please use https.");
				return;
			}
		}
		getNext().invoke(request, response);
		
	}
	
	@Override
	public String getInfo() {
		return getClass()+" 1.0. Author; Peter Somers";
	}

}
