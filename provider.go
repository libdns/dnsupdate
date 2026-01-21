// Package dnsupdate implements a DNS record management client compatible
// with the libdns interfaces for the DNS UPDATE protocol defined in RFC 2136.
package dnsupdate

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with the DNS UPDATE protocol.
type Provider struct {
	// DNS server address
	Addr string `json:"addr,omitempty"`
	// Transaction signature, with format "algo:name:secret"
	TSIG string `json:"tsig,omitempty"`
}

func (p *Provider) roundTrip(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	var client dns.Client

	if p.TSIG != "" {
		params := strings.Split(p.TSIG, ":")
		if len(params) != 3 {
			return nil, fmt.Errorf("invalid TSIG format: expected 3 fields, got %v", len(params))
		}
		algo, name, secret := params[0], params[1], params[2]
		rawSecret, err := base64.StdEncoding.DecodeString(secret)
		if err != nil {
			return nil, fmt.Errorf("invalid TSIG secret: %v", err)
		}

		client.Transfer.TSIGSigner = dns.HmacTSIG{Secret: rawSecret}

		tsig := dns.NewTSIG(name+".", algo+".", 0)
		query.Extra = append(query.Extra, tsig)
	}

	reply, _, err := client.Exchange(ctx, query, "tcp", p.Addr)
	if err != nil {
		return nil, err
	} else if reply.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS error: %v", dns.RcodeToString[reply.Rcode])
	}
	return reply, nil
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	axfr := dns.NewMsg(zone, dns.TypeAXFR)

	reply, err := p.roundTrip(ctx, axfr)
	if err != nil {
		return nil, err
	}

	return unmarshalRecords(zone, reply.Answer)
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	rrs, err := marshalRecords(zone, records)
	if err != nil {
		return nil, err
	}

	update := dns.NewMsg(zone, dns.TypeSOA)
	update.Insert(rrs)

	if _, err := p.roundTrip(ctx, &update); err != nil {
		return nil, err
	}

	return unmarshalRecords(zone, rrs)
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	axfr := dns.NewMsg(zone, dns.TypeAXFR)

	reply, err := p.roundTrip(ctx, axfr)
	if err != nil {
		return nil, err
	}

	insertRRs, err := marshalRecords(zone, records)
	if err != nil {
		return nil, err
	}

	// Build a set of RRs that are new
	m := make(map[string]struct{})
	for _, rr := range insertRRs {
		m[rr.String()] = struct{}{}
	}

	// Remove old RRs that aren't in the set of new RRs
	var removeRRs []dns.RR
	for _, rr := range reply.Answer {
		if _, ok := m[rr.String()]; ok {
			continue
		}
		removeRRs = append(removeRRs, rr)
	}

	var update dns.Msg
	update.SetUpdate(zone)
	update.Insert(insertRRs)
	update.Remove(removeRRs)

	if _, err := p.roundTrip(ctx, &update); err != nil {
		return nil, err
	}

	return unmarshalRecords(zone, insertRRs)
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	rrs := make([]dns.RR, len(records))
	for i, record := range records {
		rr, err := marshalRecord(zone, record)
		if err != nil {
			return nil, err
		}
		rrs[i] = rr
	}

	rrs, err := marshalRecords(zone, records)
	if err != nil {
		return nil, err
	}

	var update dns.Msg
	update.SetUpdate(zone)
	update.Remove(rrs)

	if _, err := p.roundTrip(ctx, &update); err != nil {
		return nil, err
	}

	return unmarshalRecords(zone, rrs)
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)

func marshalRecords(zone string, records []libdns.Record) ([]dns.RR, error) {
	rrs := make([]dns.RR, 0, len(records))
	for _, record := range records {
		rr, err := marshalRecord(zone, record)
		if err != nil {
			return rrs, err
		}
		rrs = append(rrs, rr)
	}
	return rrs, nil
}

func marshalRecord(zone string, record libdns.Record) (dns.RR, error) {
	libdnsrr := record.RR()
	fqdn := libdns.AbsoluteName(libdnsrr.Name, zone)
	ttl := uint32(libdnsrr.TTL / time.Second)
	raw := fmt.Sprintf("%v %v IN %v %v", fqdn, ttl, libdnsrr.Type, libdnsrr.Data)
	return dns.NewRR(raw)
}

func unmarshalRecords(zone string, rrs []dns.RR) ([]libdns.Record, error) {
	records := make([]libdns.Record, 0, len(rrs))
	for _, rr := range rrs {
		hdr := rr.Header()
		libdnsrr := libdns.RR{
			Name: libdns.RelativeName(hdr.Name, zone),
			TTL:  time.Duration(hdr.Ttl) * time.Second,
			Type: dns.Type(hdr.Rrtype).String(),
			Data: strings.TrimPrefix(rr.String(), hdr.String()),
		}
		record, err := libdnsrr.Parse()
		if err != nil {
			return records, err
		}
		records = append(records, record)
	}
	return records, nil
}
