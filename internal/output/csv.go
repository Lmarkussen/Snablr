package output

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"sync"

	"snablr/internal/scanner"
)

type CSVWriter struct {
	closer      io.Closer
	csvw        *csv.Writer
	mu          sync.Mutex
	wroteHeader bool
}

func NewCSVWriter(w io.Writer, closer io.Closer) *CSVWriter {
	return &CSVWriter{
		csvw:   csv.NewWriter(w),
		closer: closer,
	}
}

func (c *CSVWriter) WriteFinding(finding scanner.Finding) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.wroteHeader {
		if err := c.csvw.Write(csvHeader()); err != nil {
			return err
		}
		c.wroteHeader = true
	}

	record := []string{
		finding.Host,
		finding.Share,
		finding.ShareType,
		finding.ShareDescription,
		finding.FilePath,
		finding.RuleID,
		finding.RuleName,
		finding.Severity,
		finding.Confidence,
		finding.Category,
		strings.Join(finding.Tags, ","),
		finding.Match,
		finding.Snippet,
		finding.MatchReason,
		finding.RuleExplanation,
		finding.RuleRemediation,
		strconv.FormatBool(finding.FromSYSVOL),
		strconv.FormatBool(finding.FromNETLOGON),
		finding.Source,
		finding.DFSNamespacePath,
		finding.DFSLinkPath,
		strconv.Itoa(finding.Priority),
		finding.PriorityReason,
	}
	if err := c.csvw.Write(record); err != nil {
		return err
	}
	c.csvw.Flush()
	return c.csvw.Error()
}

func (c *CSVWriter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.csvw.Flush()
	if err := c.csvw.Error(); err != nil {
		if c.closer != nil {
			_ = c.closer.Close()
		}
		return err
	}
	if c.closer == nil {
		return nil
	}
	return c.closer.Close()
}

func csvHeader() []string {
	return []string{
		"host",
		"share",
		"share_type",
		"share_description",
		"file_path",
		"rule_id",
		"rule_name",
		"severity",
		"confidence",
		"category",
		"tags",
		"match",
		"match_snippet",
		"match_reason",
		"rule_explanation",
		"rule_remediation",
		"from_sysvol",
		"from_netlogon",
		"source",
		"dfs_namespace_path",
		"dfs_link_path",
		"priority",
		"priority_reason",
	}
}
