package pso.tomcat_security_valve;

import java.io.IOException;

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
		if (c==null) {
			getNext().invoke(request, response);
			return;
		}
		
		HttpServletRequest req=(HttpServletRequest)request;
		HttpServletResponse resp=(HttpServletResponse)response;
		String requestURI=req.getRequestURI();
		String serverName=req.getServerName();
		
		if (c.getSkipValveForHostNames().contains(serverName)) {
			getNext().invoke(request, response);
			return;
		}
		
		String remoteAddr=req.getRemoteAddr();
		if (c.getSkipValveForRemoteIps().contains(remoteAddr)) {
			getNext().invoke(request, response);
			return;
		}
		
		for (String skip:c.getSkipValveForContexts()) {
			if (requestURI.startsWith(skip)) {
				getNext().invoke(request, response);
				return;
			}
		}
		
		if (!c.getValidHosts().contains(serverName)) {
			if (c.isDebug()) {
				System.out.println("pso-tomcat-security-valve: Blocking invalid host name '"+serverName+"'");
			}
			resp.getWriter().print(c.getInvalidHostNameMessage()); // 200
			// resp.sendError(HttpServletResponse.SC_NOT_FOUND, c.getInvalidHostNameMessage()); // 404
			return;
		}
		
		if (c.isAllowOnlySecureConnections() && !req.isSecure()) {
			if (req.getMethod().equals("GET") && c.isRedirectInsecureGETRequests()) {
				if (requestURI==null || requestURI.trim().length()==0) {
					requestURI="/";
				}
				String queryString=req.getQueryString();
				if (queryString!=null && queryString.trim().length()>0) {
					queryString="?"+queryString;
				} else {
					queryString="";
				}
				resp.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
				resp.sendRedirect("https://"+serverName+requestURI+queryString);
			} else {
				resp.getWriter().print(c.getOnlySecurityConnectionsAllowedMessage());	
			}
			return;
		}
		getNext().invoke(request, response);
	}
	
	@Override
	public String getInfo() {
		return getClass()+" 1.0. Author; Peter Somers";
	}

}
