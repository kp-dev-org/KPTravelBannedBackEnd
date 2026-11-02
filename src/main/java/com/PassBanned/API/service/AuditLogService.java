package com.PassBanned.API.service;

import com.PassBanned.API.Model.AuditLog;
import com.PassBanned.API.Model.User;
import com.PassBanned.API.repository.AuditLogRepository;
import com.PassBanned.API.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class AuditLogService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private UserRepository userRepository;

    public AuditLog record(String action, String category, String description, 
                           String userEmail, String targetResource, 
                           String status, String ipAddress, String details) {
        String userName = "Système";
        String userRole = "SYSTEM";

        if (userEmail != null && !userEmail.isBlank()) {
            User user = userRepository.findByEmail(userEmail).orElse(null);
            if (user != null) {
                userName = user.getName();
                userRole = user.getRole().name();
            } else {
                userName = userEmail;
            }
        }

        // Résolution automatique de la véritable IP client (support X-Forwarded-For, reverse proxy, etc.)
        if (ipAddress == null || ipAddress.isBlank() || "192.168.1.100".equals(ipAddress)) {
            ipAddress = com.PassBanned.API.util.IpAddressUtil.getClientIp();
        }

        AuditLog log = new AuditLog(action, category, description, userEmail, 
                                    userName, userRole, targetResource, 
                                    status, ipAddress, details);
        return auditLogRepository.save(log);
    }

    public List<AuditLog> getRecentLogs() {
        return auditLogRepository.findTop50ByOrderByTimestampDesc();
    }

    public Page<AuditLog> getLogs(Pageable pageable) {
        return auditLogRepository.findAllByOrderByTimestampDesc(pageable);
    }

    public Page<AuditLog> searchLogs(String query, String category, String status, 
                                     LocalDateTime startDate, LocalDateTime endDate, 
                                     Pageable pageable) {
        return auditLogRepository.searchLogs(query, category, status, startDate, endDate, pageable);
    }

    public Map<String, Object> getAuditStats() {
        Map<String, Object> stats = new HashMap<>();
        long totalLogs = auditLogRepository.count();
        long todayLogs = auditLogRepository.countByTimestampAfter(LocalDateTime.now().minusHours(24));
        long failedLogs = auditLogRepository.countByStatus("FAILURE");
        long warningLogs = auditLogRepository.countByStatus("WARNING");

        stats.put("totalLogs", totalLogs);
        stats.put("todayLogs", todayLogs);
        stats.put("failedLogs", failedLogs);
        stats.put("warningLogs", warningLogs);
        return stats;
    }
}
