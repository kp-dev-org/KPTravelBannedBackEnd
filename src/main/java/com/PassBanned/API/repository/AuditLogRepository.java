package com.PassBanned.API.repository;

import com.PassBanned.API.Model.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findTop50ByOrderByTimestampDesc();

    Page<AuditLog> findAllByOrderByTimestampDesc(Pageable pageable);


    @Query(value = """
    SELECT a.*
    FROM audit_logs a
    WHERE
        (
            CAST(:query AS text) IS NULL
            OR CAST(:query AS text) = ''
            OR LOWER(COALESCE(a.description, '')) LIKE
                '%' || LOWER(CAST(:query AS text)) || '%'
            OR LOWER(COALESCE(a.user_email, '')) LIKE
                '%' || LOWER(CAST(:query AS text)) || '%'
            OR LOWER(COALESCE(a.user_name, '')) LIKE
                '%' || LOWER(CAST(:query AS text)) || '%'
            OR LOWER(COALESCE(a.target_resource, '')) LIKE
                '%' || LOWER(CAST(:query AS text)) || '%'
            OR LOWER(COALESCE(a.action, '')) LIKE
                '%' || LOWER(CAST(:query AS text)) || '%'
        )
        AND (
            CAST(:category AS text) IS NULL
            OR CAST(:category AS text) = ''
            OR a.category = CAST(:category AS text)
        )
        AND (
            CAST(:status AS text) IS NULL
            OR CAST(:status AS text) = ''
            OR a.status = CAST(:status AS text)
        )
        AND (
            CAST(:startDate AS timestamp) IS NULL
            OR a.timestamp >= CAST(:startDate AS timestamp)
        )
        AND (
            CAST(:endDate AS timestamp) IS NULL
            OR a.timestamp <= CAST(:endDate AS timestamp)
        )
    ORDER BY a.timestamp DESC
    """,
            countQuery = """
    SELECT COUNT(*)
    FROM audit_logs a
    WHERE
        (
            CAST(:query AS text) IS NULL
            OR CAST(:query AS text) = ''
            OR LOWER(COALESCE(a.description, '')) LIKE
                '%' || LOWER(CAST(:query AS text)) || '%'
            OR LOWER(COALESCE(a.user_email, '')) LIKE
                '%' || LOWER(CAST(:query AS text)) || '%'
            OR LOWER(COALESCE(a.user_name, '')) LIKE
                '%' || LOWER(CAST(:query AS text)) || '%'
            OR LOWER(COALESCE(a.target_resource, '')) LIKE
                '%' || LOWER(CAST(:query AS text)) || '%'
            OR LOWER(COALESCE(a.action, '')) LIKE
                '%' || LOWER(CAST(:query AS text)) || '%'
        )
        AND (
            CAST(:category AS text) IS NULL
            OR CAST(:category AS text) = ''
            OR a.category = CAST(:category AS text)
        )
        AND (
            CAST(:status AS text) IS NULL
            OR CAST(:status AS text) = ''
            OR a.status = CAST(:status AS text)
        )
        AND (
            CAST(:startDate AS timestamp) IS NULL
            OR a.timestamp >= CAST(:startDate AS timestamp)
        )
        AND (
            CAST(:endDate AS timestamp) IS NULL
            OR a.timestamp <= CAST(:endDate AS timestamp)
        )
    """,
            nativeQuery = true)
    Page<AuditLog> searchLogs(
            @Param("query") String query,
            @Param("category") String category,
            @Param("status") String status,
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate,
            Pageable pageable
    );


    long countByTimestampAfter(LocalDateTime start);

    long countByStatus(String status);
}
