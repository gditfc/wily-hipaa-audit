package io.csra.wily.hipaa.audit.service.impl;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.lang3.reflect.MethodUtils;
import io.csra.wily.hipaa.audit.model.HipaaEventDTO;
import io.csra.wily.hipaa.audit.service.HipaaAuditLogService;
import io.csra.wily.security.model.UserDTO;
import io.csra.wily.security.service.SecurityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component("hipaaAuditLogService")
public class HipaaAuditLogServiceImpl implements HipaaAuditLogService {

	private static final String AUDIT_LOGGER_NAME = "HipaaAuditLogger";

	private static final Logger LOGGER = LoggerFactory.getLogger(HipaaAuditLogServiceImpl.class);
	private static final Logger AUDIT_LOGGER = LoggerFactory.getLogger(AUDIT_LOGGER_NAME);

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private SecurityService securityService;

	public void generateLogs(Object o, String eventType, String app, String function) {
		try {
			writeLogs(getHipaaEvents(o, eventType, app, function));
		} catch (NoSuchFieldException e) {
			LOGGER.trace("No Client ID Found - Not Logging", e);
		}
	}

	/**
	 * This method inspects the response object, gathers the user information and produces either a single event or a list of
	 * events, assuming a list of transactions or clients were returned via an endpoint.
	 */
	private List<HipaaEventDTO> getHipaaEvents(Object o, String eventType, String app, String function) throws NoSuchFieldException {
		List<HipaaEventDTO> events = new ArrayList<>();
		UserDTO user = securityService.getLoggedInUser();

		if (o instanceof Collection<?>) {
			for (Object obj : (Collection<?>) o) {
				events.add(extractHipaaEventDTO(obj, eventType, app, function, user));
			}
		} else {
			events.add(extractHipaaEventDTO(o, eventType, app, function, user));
		}

		return events;
	}

	/**
	 * This method will produce the event object and will make the necessary call to extract the client ID from the
	 * endpoint's response.
	 */
	private HipaaEventDTO extractHipaaEventDTO(Object o, String eventType, String app, String function, UserDTO user) throws NoSuchFieldException {
		HipaaEventDTO dto = new HipaaEventDTO();
		dto.setApp(app);
		dto.setClientId(extractClientId(o));
		dto.setFunction(function);
		dto.setProviders(user.getProviderIds());
		dto.setRole(StringUtils.isNotBlank(user.getRole()) ? user.getRole() : "ROLE_USER");
		dto.setTimestamp(new Date());
		dto.setType(eventType);
		dto.setUserName(user.getUserId());

		return dto;
	}

	/**
	 * This delegating method will first attempt to gather the client ID from a field on the object "clientId" and will only
	 * attempt to gather the data from the "getClientId()" method if it is unable to find it off a simple field.
	 */
	private String extractClientId(Object o) throws NoSuchFieldException {
		String returnValue = null;

		returnValue = extractClientIdFromField(o);
		returnValue = returnValue != null ? returnValue : extractClientIdFromMethod(o);

		if (returnValue != null) {
			return returnValue;
		}

		throw new NoSuchFieldException();
	}

	/**
	 * Uses reflection to extract the clientId from a field of the same name.
	 */
	private String extractClientIdFromField(Object o) {
		try {
			Field field = FieldUtils.getField(o.getClass(), "clientId", true);
			field.setAccessible(true);

			Object returnValue = field.get(o);

			if (returnValue != null) {
				return returnValue.toString();
			}
		} catch (SecurityException e) {
			LOGGER.trace("No Access to Field", e);
		} catch (IllegalArgumentException e) {
			LOGGER.trace("Bad Argument to Retrieve Field", e);
		} catch (IllegalAccessException e) {
			LOGGER.trace("Illegal Access to Field", e);
		}

		return null;
	}

	/**
	 * Uses reflection to gather the clientId from a getClientId() method on the class.
	 */
	private String extractClientIdFromMethod(Object o) {
		try {
			Method method = MethodUtils.getMatchingMethod(o.getClass(), "getClientId");
			method.setAccessible(true);

			Object returnValue = method.invoke(o);

			if (returnValue != null) {
				return returnValue.toString();
			}
		} catch (IllegalAccessException e) {
			LOGGER.debug("Illegal Access to Method", e);
		} catch (InvocationTargetException e) {
			LOGGER.debug("Failed to Invoke Method", e);
		}

		return null;
	}

	/**
	 * After event objects are generated, this method will log all of the events to file, which will later be retrieved by a
	 * log shipper of some sort and delivered to a final data store.
	 */
	private void writeLogs(List<HipaaEventDTO> events) {
		for (HipaaEventDTO event : events) {
			try {
				AUDIT_LOGGER.info(objectMapper.writeValueAsString(event));
			} catch (JsonProcessingException e) {
				LOGGER.error("Failure in converting JSON", e);
			}
		}

		LOGGER.info("Hipaa Audit Logs Recorded.");
	}

}
