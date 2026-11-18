package findings

import (
	"snablr/internal/credentialanalysis"
	"snablr/internal/termsafe"
)

// The Finder renders persisted evidence, file paths, share names and
// recovered values into an interactive terminal. These helpers return display
// copies whose free-text fields cannot inject terminal control sequences.
// Lookup keys (persisted refs, finding refs, correlation keys) stay exact, and
// the persisted data and exports are never modified.

func safeCategories(categories []category) []category {
	if len(categories) == 0 {
		return categories
	}
	out := make([]category, len(categories))
	for index, item := range categories {
		item.Discoveries = safeDiscoveries(item.Discoveries)
		out[index] = item
	}
	return out
}

func safeDiscoveries(discoveries []discovery) []discovery {
	if len(discoveries) == 0 {
		return discoveries
	}
	out := make([]discovery, len(discoveries))
	for index, d := range discoveries {
		out[index] = safeDiscovery(d)
	}
	return out
}

func safeDiscovery(d discovery) discovery {
	d.Title = termsafe.Text(d.Title)
	d.Subcategory = termsafe.Text(d.Subcategory)
	d.MaterialType = termsafe.Text(d.MaterialType)
	d.Identity = termsafe.Text(d.Identity)
	d.Domain = termsafe.Text(d.Domain)
	d.MaterialFamily = termsafe.Text(d.MaterialFamily)
	d.SourceContext = termsafe.Text(d.SourceContext)
	d.OriginType = termsafe.Text(d.OriginType)
	d.Value = termsafe.Text(d.Value)
	d.Host = termsafe.Text(d.Host)
	d.Share = termsafe.Text(d.Share)
	d.Path = termsafe.Text(d.Path)
	d.Confidence = termsafe.Text(d.Confidence)
	d.Verification = termsafe.Text(d.Verification)
	d.KeyFormat = termsafe.Text(d.KeyFormat)
	d.KeyAlgorithm = termsafe.Text(d.KeyAlgorithm)
	d.KeyStatus = termsafe.Text(d.KeyStatus)
	d.RecoveredPassword = termsafe.Text(d.RecoveredPassword)
	d.Reason = termsafe.Text(d.Reason)
	d.PairingStatus = termsafe.Text(d.PairingStatus)
	d.PairingBasis = termsafe.Text(d.PairingBasis)
	d.OriginalVerification = termsafe.Text(d.OriginalVerification)
	d.CorrelationIdentity = termsafe.Text(d.CorrelationIdentity)
	d.CorrelationDomain = termsafe.Text(d.CorrelationDomain)
	d.CorrelationConfidenceRationale = termsafe.Text(d.CorrelationConfidenceRationale)
	d.Evidence = termsafe.Lines(d.Evidence)
	d.Sources = termsafe.Lines(d.Sources)
	if len(d.ConnectionDetails) > 0 {
		details := make([]connectionDetail, len(d.ConnectionDetails))
		for index, detail := range d.ConnectionDetails {
			details[index] = connectionDetail{Label: termsafe.Text(detail.Label), Value: termsafe.Text(detail.Value)}
		}
		d.ConnectionDetails = details
	}
	if len(d.CorrelationSources) > 0 {
		sources := make([]credentialanalysis.CorrelationSource, len(d.CorrelationSources))
		for index, source := range d.CorrelationSources {
			sources[index] = safeCorrelationSource(source)
		}
		d.CorrelationSources = sources
	}
	if d.Finding != nil {
		finding := termsafe.Finding(*d.Finding)
		d.Finding = &finding
	}
	return d
}

func safeCorrelationSource(source credentialanalysis.CorrelationSource) credentialanalysis.CorrelationSource {
	source.Host = termsafe.Text(source.Host)
	source.Share = termsafe.Text(source.Share)
	source.Path = termsafe.Text(source.Path)
	source.Container = termsafe.Text(source.Container)
	if len(source.Evidence) > 0 {
		evidence := make([]credentialanalysis.Evidence, len(source.Evidence))
		for index, item := range source.Evidence {
			item.Source = termsafe.Text(item.Source)
			item.Path = termsafe.Text(item.Path)
			item.Location = termsafe.Text(item.Location)
			evidence[index] = item
		}
		source.Evidence = evidence
	}
	return source
}

// safeEvidenceItem makes fetched evidence (a finding, a credential candidate
// or a raw correlation payload) safe to display.
func safeEvidenceItem(item evidenceCacheItem) evidenceCacheItem {
	if item.finding != nil {
		finding := termsafe.Finding(*item.finding)
		item.finding = &finding
	}
	if item.candidate != nil {
		candidate := termsafe.Candidate(*item.candidate)
		item.candidate = &candidate
	}
	item.correlation = termsafe.Text(item.correlation)
	return item
}

func safeGlobalSearchResults(results []GlobalSearchResult) []GlobalSearchResult {
	if len(results) == 0 {
		return results
	}
	out := make([]GlobalSearchResult, len(results))
	for index, result := range results {
		result.Field = termsafe.Text(result.Field)
		result.Value = termsafe.Text(result.Value)
		result.Context = termsafe.Text(result.Context)
		out[index] = result
	}
	return out
}
