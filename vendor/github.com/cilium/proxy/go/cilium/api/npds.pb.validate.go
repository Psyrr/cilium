// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: cilium/api/npds.proto

package cilium

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang/protobuf/ptypes"

	core "github.com/cilium/proxy/go/envoy/api/v2/core"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = ptypes.DynamicAny{}

	_ = core.SocketAddress_Protocol(0)
)

// define the regex for a UUID once up-front
var _npds_uuidPattern = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

// Validate checks the field values on NetworkPolicy with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *NetworkPolicy) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Name

	// no validation rules for Policy

	for idx, item := range m.GetIngressPerPortPolicies() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return NetworkPolicyValidationError{
					field:  fmt.Sprintf("IngressPerPortPolicies[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetEgressPerPortPolicies() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return NetworkPolicyValidationError{
					field:  fmt.Sprintf("EgressPerPortPolicies[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	// no validation rules for ConntrackMapName

	return nil
}

// NetworkPolicyValidationError is the validation error returned by
// NetworkPolicy.Validate if the designated constraints aren't met.
type NetworkPolicyValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e NetworkPolicyValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e NetworkPolicyValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e NetworkPolicyValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e NetworkPolicyValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e NetworkPolicyValidationError) ErrorName() string { return "NetworkPolicyValidationError" }

// Error satisfies the builtin error interface
func (e NetworkPolicyValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sNetworkPolicy.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = NetworkPolicyValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = NetworkPolicyValidationError{}

// Validate checks the field values on PortNetworkPolicy with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *PortNetworkPolicy) Validate() error {
	if m == nil {
		return nil
	}

	if m.GetPort() > 65535 {
		return PortNetworkPolicyValidationError{
			field:  "Port",
			reason: "value must be less than or equal to 65535",
		}
	}

	// no validation rules for Protocol

	for idx, item := range m.GetRules() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return PortNetworkPolicyValidationError{
					field:  fmt.Sprintf("Rules[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// PortNetworkPolicyValidationError is the validation error returned by
// PortNetworkPolicy.Validate if the designated constraints aren't met.
type PortNetworkPolicyValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e PortNetworkPolicyValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e PortNetworkPolicyValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e PortNetworkPolicyValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e PortNetworkPolicyValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e PortNetworkPolicyValidationError) ErrorName() string {
	return "PortNetworkPolicyValidationError"
}

// Error satisfies the builtin error interface
func (e PortNetworkPolicyValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sPortNetworkPolicy.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = PortNetworkPolicyValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = PortNetworkPolicyValidationError{}

// Validate checks the field values on TLSContext with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *TLSContext) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for TrustedCa

	// no validation rules for CertificateChain

	// no validation rules for PrivateKey

	return nil
}

// TLSContextValidationError is the validation error returned by
// TLSContext.Validate if the designated constraints aren't met.
type TLSContextValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e TLSContextValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e TLSContextValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e TLSContextValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e TLSContextValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e TLSContextValidationError) ErrorName() string { return "TLSContextValidationError" }

// Error satisfies the builtin error interface
func (e TLSContextValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sTLSContext.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = TLSContextValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = TLSContextValidationError{}

// Validate checks the field values on PortNetworkPolicyRule with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *PortNetworkPolicyRule) Validate() error {
	if m == nil {
		return nil
	}

	_PortNetworkPolicyRule_RemotePolicies_Unique := make(map[uint64]struct{}, len(m.GetRemotePolicies()))

	for idx, item := range m.GetRemotePolicies() {
		_, _ = idx, item

		if _, exists := _PortNetworkPolicyRule_RemotePolicies_Unique[item]; exists {
			return PortNetworkPolicyRuleValidationError{
				field:  fmt.Sprintf("RemotePolicies[%v]", idx),
				reason: "repeated value must contain unique items",
			}
		} else {
			_PortNetworkPolicyRule_RemotePolicies_Unique[item] = struct{}{}
		}

		// no validation rules for RemotePolicies[idx]
	}

	if v, ok := interface{}(m.GetDownstreamTlsContext()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return PortNetworkPolicyRuleValidationError{
				field:  "DownstreamTlsContext",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetUpstreamTlsContext()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return PortNetworkPolicyRuleValidationError{
				field:  "UpstreamTlsContext",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for L7Proto

	switch m.L7.(type) {

	case *PortNetworkPolicyRule_HttpRules:

		if v, ok := interface{}(m.GetHttpRules()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return PortNetworkPolicyRuleValidationError{
					field:  "HttpRules",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *PortNetworkPolicyRule_KafkaRules:

		if v, ok := interface{}(m.GetKafkaRules()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return PortNetworkPolicyRuleValidationError{
					field:  "KafkaRules",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *PortNetworkPolicyRule_L7Rules:

		if v, ok := interface{}(m.GetL7Rules()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return PortNetworkPolicyRuleValidationError{
					field:  "L7Rules",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// PortNetworkPolicyRuleValidationError is the validation error returned by
// PortNetworkPolicyRule.Validate if the designated constraints aren't met.
type PortNetworkPolicyRuleValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e PortNetworkPolicyRuleValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e PortNetworkPolicyRuleValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e PortNetworkPolicyRuleValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e PortNetworkPolicyRuleValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e PortNetworkPolicyRuleValidationError) ErrorName() string {
	return "PortNetworkPolicyRuleValidationError"
}

// Error satisfies the builtin error interface
func (e PortNetworkPolicyRuleValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sPortNetworkPolicyRule.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = PortNetworkPolicyRuleValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = PortNetworkPolicyRuleValidationError{}

// Validate checks the field values on HttpNetworkPolicyRules with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *HttpNetworkPolicyRules) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetHttpRules()) < 1 {
		return HttpNetworkPolicyRulesValidationError{
			field:  "HttpRules",
			reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetHttpRules() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return HttpNetworkPolicyRulesValidationError{
					field:  fmt.Sprintf("HttpRules[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// HttpNetworkPolicyRulesValidationError is the validation error returned by
// HttpNetworkPolicyRules.Validate if the designated constraints aren't met.
type HttpNetworkPolicyRulesValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HttpNetworkPolicyRulesValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HttpNetworkPolicyRulesValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HttpNetworkPolicyRulesValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HttpNetworkPolicyRulesValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HttpNetworkPolicyRulesValidationError) ErrorName() string {
	return "HttpNetworkPolicyRulesValidationError"
}

// Error satisfies the builtin error interface
func (e HttpNetworkPolicyRulesValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHttpNetworkPolicyRules.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HttpNetworkPolicyRulesValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HttpNetworkPolicyRulesValidationError{}

// Validate checks the field values on HttpNetworkPolicyRule with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *HttpNetworkPolicyRule) Validate() error {
	if m == nil {
		return nil
	}

	for idx, item := range m.GetHeaders() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return HttpNetworkPolicyRuleValidationError{
					field:  fmt.Sprintf("Headers[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	// no validation rules for ImposeHeaders

	return nil
}

// HttpNetworkPolicyRuleValidationError is the validation error returned by
// HttpNetworkPolicyRule.Validate if the designated constraints aren't met.
type HttpNetworkPolicyRuleValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HttpNetworkPolicyRuleValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HttpNetworkPolicyRuleValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HttpNetworkPolicyRuleValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HttpNetworkPolicyRuleValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HttpNetworkPolicyRuleValidationError) ErrorName() string {
	return "HttpNetworkPolicyRuleValidationError"
}

// Error satisfies the builtin error interface
func (e HttpNetworkPolicyRuleValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHttpNetworkPolicyRule.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HttpNetworkPolicyRuleValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HttpNetworkPolicyRuleValidationError{}

// Validate checks the field values on KafkaNetworkPolicyRules with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *KafkaNetworkPolicyRules) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetKafkaRules()) < 1 {
		return KafkaNetworkPolicyRulesValidationError{
			field:  "KafkaRules",
			reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetKafkaRules() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return KafkaNetworkPolicyRulesValidationError{
					field:  fmt.Sprintf("KafkaRules[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// KafkaNetworkPolicyRulesValidationError is the validation error returned by
// KafkaNetworkPolicyRules.Validate if the designated constraints aren't met.
type KafkaNetworkPolicyRulesValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e KafkaNetworkPolicyRulesValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e KafkaNetworkPolicyRulesValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e KafkaNetworkPolicyRulesValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e KafkaNetworkPolicyRulesValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e KafkaNetworkPolicyRulesValidationError) ErrorName() string {
	return "KafkaNetworkPolicyRulesValidationError"
}

// Error satisfies the builtin error interface
func (e KafkaNetworkPolicyRulesValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sKafkaNetworkPolicyRules.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = KafkaNetworkPolicyRulesValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = KafkaNetworkPolicyRulesValidationError{}

// Validate checks the field values on KafkaNetworkPolicyRule with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *KafkaNetworkPolicyRule) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for ApiKey

	// no validation rules for ApiVersion

	if utf8.RuneCountInString(m.GetTopic()) > 255 {
		return KafkaNetworkPolicyRuleValidationError{
			field:  "Topic",
			reason: "value length must be at most 255 runes",
		}
	}

	if !_KafkaNetworkPolicyRule_Topic_Pattern.MatchString(m.GetTopic()) {
		return KafkaNetworkPolicyRuleValidationError{
			field:  "Topic",
			reason: "value does not match regex pattern \"^[a-zA-Z0-9._-]*$\"",
		}
	}

	if !_KafkaNetworkPolicyRule_ClientId_Pattern.MatchString(m.GetClientId()) {
		return KafkaNetworkPolicyRuleValidationError{
			field:  "ClientId",
			reason: "value does not match regex pattern \"^[a-zA-Z0-9._-]*$\"",
		}
	}

	return nil
}

// KafkaNetworkPolicyRuleValidationError is the validation error returned by
// KafkaNetworkPolicyRule.Validate if the designated constraints aren't met.
type KafkaNetworkPolicyRuleValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e KafkaNetworkPolicyRuleValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e KafkaNetworkPolicyRuleValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e KafkaNetworkPolicyRuleValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e KafkaNetworkPolicyRuleValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e KafkaNetworkPolicyRuleValidationError) ErrorName() string {
	return "KafkaNetworkPolicyRuleValidationError"
}

// Error satisfies the builtin error interface
func (e KafkaNetworkPolicyRuleValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sKafkaNetworkPolicyRule.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = KafkaNetworkPolicyRuleValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = KafkaNetworkPolicyRuleValidationError{}

var _KafkaNetworkPolicyRule_Topic_Pattern = regexp.MustCompile("^[a-zA-Z0-9._-]*$")

var _KafkaNetworkPolicyRule_ClientId_Pattern = regexp.MustCompile("^[a-zA-Z0-9._-]*$")

// Validate checks the field values on L7NetworkPolicyRules with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *L7NetworkPolicyRules) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetL7Rules()) < 1 {
		return L7NetworkPolicyRulesValidationError{
			field:  "L7Rules",
			reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetL7Rules() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return L7NetworkPolicyRulesValidationError{
					field:  fmt.Sprintf("L7Rules[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// L7NetworkPolicyRulesValidationError is the validation error returned by
// L7NetworkPolicyRules.Validate if the designated constraints aren't met.
type L7NetworkPolicyRulesValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e L7NetworkPolicyRulesValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e L7NetworkPolicyRulesValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e L7NetworkPolicyRulesValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e L7NetworkPolicyRulesValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e L7NetworkPolicyRulesValidationError) ErrorName() string {
	return "L7NetworkPolicyRulesValidationError"
}

// Error satisfies the builtin error interface
func (e L7NetworkPolicyRulesValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sL7NetworkPolicyRules.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = L7NetworkPolicyRulesValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = L7NetworkPolicyRulesValidationError{}

// Validate checks the field values on L7NetworkPolicyRule with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *L7NetworkPolicyRule) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Rule

	return nil
}

// L7NetworkPolicyRuleValidationError is the validation error returned by
// L7NetworkPolicyRule.Validate if the designated constraints aren't met.
type L7NetworkPolicyRuleValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e L7NetworkPolicyRuleValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e L7NetworkPolicyRuleValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e L7NetworkPolicyRuleValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e L7NetworkPolicyRuleValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e L7NetworkPolicyRuleValidationError) ErrorName() string {
	return "L7NetworkPolicyRuleValidationError"
}

// Error satisfies the builtin error interface
func (e L7NetworkPolicyRuleValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sL7NetworkPolicyRule.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = L7NetworkPolicyRuleValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = L7NetworkPolicyRuleValidationError{}
