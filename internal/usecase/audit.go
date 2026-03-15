package usecase

import (
	"context"
	"fmt"
	"time"
)

type AuditUseCase struct {
	audits AuditRepository
	idGen  IDGenerator
}

func NewAuditUseCase(audits AuditRepository, idGen IDGenerator) *AuditUseCase {
	return &AuditUseCase{audits: audits, idGen: idGen}
}

type AuditEntry struct {
	Action    string
	Category  string
	Detail    string
	IPAddress string
	UserAgent string
	CreatedAt time.Time
}

type AuditPage struct {
	Entries    []AuditEntry
	Total      int
	Page       int
	PageSize   int
	TotalPages int
}

const auditPageSize = 20

func (uc *AuditUseCase) List(ctx context.Context, userID string, category string, page int) (*AuditPage, error) {
	if page < 1 {
		page = 1
	}

	total, err := uc.audits.CountByUser(ctx, userID, category)
	if err != nil {
		return nil, fmt.Errorf("counting audit logs: %w", err)
	}

	totalPages := (total + auditPageSize - 1) / auditPageSize
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	offset := (page - 1) * auditPageSize
	logs, err := uc.audits.ListByUser(ctx, userID, category, auditPageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("listing audit logs: %w", err)
	}

	entries := make([]AuditEntry, 0, len(logs))
	for _, l := range logs {
		entries = append(entries, AuditEntry{
			Action:    string(l.Action),
			Category:  string(l.Category),
			Detail:    l.Detail,
			IPAddress: l.IPAddress,
			UserAgent: l.UserAgent,
			CreatedAt: l.CreatedAt,
		})
	}

	return &AuditPage{
		Entries:    entries,
		Total:      total,
		Page:       page,
		PageSize:   auditPageSize,
		TotalPages: totalPages,
	}, nil
}

func (uc *AuditUseCase) Cleanup(ctx context.Context) error {
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	return uc.audits.DeleteOlderThan(ctx, cutoff)
}
