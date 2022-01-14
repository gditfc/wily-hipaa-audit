package io.csra.wily.hipaa.audit.service;

public interface HipaaAuditLogService {

    void generateLogs(Object o, String eventType, String app, String function);

}
