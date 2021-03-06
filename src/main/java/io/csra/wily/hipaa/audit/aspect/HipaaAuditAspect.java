package io.csra.wily.hipaa.audit.aspect;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import io.csra.wily.hipaa.audit.annotation.HipaaAudit;
import io.csra.wily.hipaa.audit.service.HipaaAuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * The intent of this aspect is to capture all HIPAA Events generated by the PTAR system. Any RESTful endpoint in the system
 * simply needs to have the @HipaaAudit annotation applied to it for data to be captured. The expectation of this aspect is
 * that the returned object from the endpoint contains a clientId field or a getClientId() method. This will allow us to tag
 * the event generated for that particular client. Furthermore, the annotation should specify the type of event, that way we
 * can accurately tag the event for later reporting.
 * 
 * @author Nick DiMola
 * 
 */
@Aspect
@Component
public class HipaaAuditAspect {

	private final HipaaAuditLogService hipaaAuditLogService;

	public HipaaAuditAspect(HipaaAuditLogService hipaaAuditLogService) {
		this.hipaaAuditLogService = hipaaAuditLogService;
	}

	/**
	 * This method will be invoked automagically by Spring whenever the @HipaaAudit annotation is applied to a RESTful
	 * endpoint.
	 * 
	 * @param pjp JoinPoint
	 * @param hipaaAudit Audit Annotation
	 * @return The proceeding object to continue aspect execution
	 * @throws Throwable
	 */
	@Around(value = "@annotation(hipaaAudit)", argNames = "hipaaAudit")
	public Object aroundAdvice(ProceedingJoinPoint pjp, HipaaAudit hipaaAudit) throws Throwable {
		Object o = pjp.proceed();

		hipaaAuditLogService.generateLogs(o, hipaaAudit.type(), hipaaAudit.app(), hipaaAudit.function());

		return o;
	}
}
