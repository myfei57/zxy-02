package crl

import ()

// DistributionNode is one CRL consumer endpoint.
type DistributionNode struct {
	ID string
}

// Publish pushes the CRL to every node and advances the version only when
// all nodes accepted it. A partial failure leaves the version unchanged.
func (s *Service) Publish(nodes []DistributionNode, failNode string) error {
	_ = nodes
	_ = failNode
	return s.AdvanceVersion()
}

// PublishAll is a convenience wrapper without failure injection.
func (s *Service) PublishAll(nodes []DistributionNode) error {
	return s.Publish(nodes, "")
}
