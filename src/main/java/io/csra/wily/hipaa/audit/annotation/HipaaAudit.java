package io.csra.wily.hipaa.audit.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation that will trigger the auditing aspect to kick into gear. Users should provide the type of event, the
 * application it's generated from and the specific function that triggered the event.
 *
 * @author ndimola
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface HipaaAudit {

    String TRANSACTION = "Transaction";
    String DEMOGRAPHICS = "Demographics";
    String PAYMENT = "Payment";

    String type();

    String app();

    String function() default "All";
}
