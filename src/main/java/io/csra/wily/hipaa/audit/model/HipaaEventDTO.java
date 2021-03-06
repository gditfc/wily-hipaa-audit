package io.csra.wily.hipaa.audit.model;

import java.util.Date;
import java.util.List;

/**
 * DTO that represents a HIPAA Event. Generated by the auditing service, for serialization to log file.
 *
 * @author ndimola
 *
 */
public class HipaaEventDTO {

	private String clientId;
	private String app;
	private String function;
	private String type;
	private String userName;
	private String role;
	private List<String> providers;
	private Date timestamp;

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getApp() {
		return app;
	}

	public void setApp(String app) {
		this.app = app;
	}

	public String getFunction() {
		return function;
	}

	public void setFunction(String function) {
		this.function = function;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}

	public List<String> getProviders() {
		return providers;
	}

	public void setProviders(List<String> providers) {
		this.providers = providers;
	}

	public Date getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(Date timestamp) {
		this.timestamp = timestamp;
	}

}
