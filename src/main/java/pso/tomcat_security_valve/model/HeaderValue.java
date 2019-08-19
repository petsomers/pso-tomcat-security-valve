package pso.tomcat_security_valve.model;

public class HeaderValue {
	final private String header;
	final private String value;
	
	public HeaderValue(final String header, final String value) {
		this.header=header;
		this.value=value;
	}
	
	public String getHeader() {
		return header;
	}
	
	public String getValue() {
		return value;
	}
}
