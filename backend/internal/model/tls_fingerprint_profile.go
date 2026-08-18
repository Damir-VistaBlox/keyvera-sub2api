// Package model 定义服务层使用的数据模型。
package model

import (
	"fmt"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
)

// TLSFingerprintProfile TLS 指纹配置模板
// 包含完整的 ClientHello 参数，用于模拟特定客户端的 TLS 握手特征
type TLSFingerprintProfile struct {
	ID                  int64     `json:"id"`
	Name                string    `json:"name"`
	Description         *string   `json:"description"`
	EnableGREASE        bool      `json:"enable_grease"`
	CipherSuites        []uint16  `json:"cipher_suites"`
	Curves              []uint16  `json:"curves"`
	PointFormats        []uint16  `json:"point_formats"`
	SignatureAlgorithms []uint16  `json:"signature_algorithms"`
	ALPNProtocols       []string  `json:"alpn_protocols"`
	SupportedVersions   []uint16  `json:"supported_versions"`
	KeyShareGroups      []uint16  `json:"key_share_groups"`
	PSKModes            []uint16  `json:"psk_modes"`
	Extensions          []uint16  `json:"extensions"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// Validate 验证模板配置的有效性
func (p *TLSFingerprintProfile) Validate() error {
	if p.Name == "" {
		return &ValidationError{Field: "name", Message: "name is required"}
	}
	// PointFormats 和 PSKModes 在 dialer 中会被下转为 uint8（TLS 协议要求），
	// 超出 uint8 范围的值会被静默截断，产生与配置不符的指纹。
	if err := validateUint8Range("point_formats", p.PointFormats); err != nil {
		return err
	}
	if err := validateUint8Range("psk_modes", p.PSKModes); err != nil {
		return err
	}
	return nil
}

func validateUint8Range(field string, vals []uint16) error {
	for _, v := range vals {
		if v > 255 {
			return &ValidationError{Field: field, Message: fmt.Sprintf("value %d exceeds the maximum of 255", v)}
		}
	}
	return nil
}

// ToTLSProfile 将领域模型转换为运行时使用的 tlsfingerprint.Profile
// 空切片字段会在 dialer 中 fallback 到内置默认值
func (p *TLSFingerprintProfile) ToTLSProfile() *tlsfingerprint.Profile {
	return &tlsfingerprint.Profile{
		Name:                p.Name,
		EnableGREASE:        p.EnableGREASE,
		CipherSuites:        p.CipherSuites,
		Curves:              p.Curves,
		PointFormats:        p.PointFormats,
		SignatureAlgorithms: p.SignatureAlgorithms,
		ALPNProtocols:       p.ALPNProtocols,
		SupportedVersions:   p.SupportedVersions,
		KeyShareGroups:      p.KeyShareGroups,
		PSKModes:            p.PSKModes,
		Extensions:          p.Extensions,
	}
}
