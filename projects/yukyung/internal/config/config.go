package config

import (
	"fmt"
	"net"
	"time"

	"github.com/spf13/viper"
)

// Config는 라우터의 전체 설정을 담는 구조체입니다
type Config struct {
	Router       RouterConfig   `yaml:"router" mapstructure:"router"`
	Network      NetworkConfig  `yaml:"network" mapstructure:"network"`
	Logging      LoggingConfig  `yaml:"logging" mapstructure:"logging"`
	RoutingRules []*RoutingRule `yaml:"routing_rules" mapstructure:"routing_rules"`
}

// RouterConfig는 라우터 동작 설정입니다
type RouterConfig struct {
	DefaultAction  string        `yaml:"default_action" mapstructure:"default_action"`
	UpdateInterval time.Duration `yaml:"update_interval" mapstructure:"update_interval"`
	MaxRules       int           `yaml:"max_rules" mapstructure:"max_rules"`
}

// NetworkConfig는 네트워크 인터페이스 설정입니다
type NetworkConfig struct {
	Interface string `yaml:"interface" mapstructure:"interface"`
}

// LoggingConfig는 로깅 설정입니다
type LoggingConfig struct {
	Level  string `yaml:"level" mapstructure:"level"`
	Format string `yaml:"format" mapstructure:"format"`
}

// RoutingRule은 패킷 라우팅 규칙을 정의합니다
type RoutingRule struct {
	ID                int    `yaml:"id" mapstructure:"id"`
	Name              string `yaml:"name" mapstructure:"name"`
	SrcIP             string `yaml:"src_ip" mapstructure:"src_ip"`
	SrcPort           int    `yaml:"src_port" mapstructure:"src_port"`
	DstIP             string `yaml:"dst_ip" mapstructure:"dst_ip"`
	DstPort           int    `yaml:"dst_port" mapstructure:"dst_port"`
	Protocol          string `yaml:"protocol" mapstructure:"protocol"`                     // 프로토콜 (tcp/udp/icmp)
	Action            string `yaml:"action" mapstructure:"action"`                         // 액션 (pass/drop/redirect)
	RedirectInterface string `yaml:"redirect_interface" mapstructure:"redirect_interface"` // 리다이렉트 대상 인터페이스
	Priority          int    `yaml:"priority" mapstructure:"priority"`                     // 우선순위 (0-100)
	Enabled           bool   `yaml:"enabled" mapstructure:"enabled"`                       // 활성화 여부
}

// LoadConfig는 설정 파일을 로드합니다
func LoadConfig(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	// 기본값 설정
	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("설정 파일 읽기 실패: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("설정 파싱 실패: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("설정 검증 실패: %w", err)
	}

	return &config, nil
}

// setDefaults는 기본 설정값을 지정합니다
func setDefaults() {
	viper.SetDefault("router.default_action", "drop")
	viper.SetDefault("router.update_interval", "5s")
	viper.SetDefault("router.max_rules", 100)
	viper.SetDefault("network.interface", "lo")
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "text")
}

// Validate는 설정 유효성을 검사합니다
func (c *Config) Validate() error {
	// 기본 액션 검증
	if c.Router.DefaultAction == "" {
		return fmt.Errorf("기본 액션이 설정되지 않았습니다")
	}

	if c.Router.DefaultAction != "pass" && c.Router.DefaultAction != "drop" {
		return fmt.Errorf("잘못된 기본 액션: %s (pass 또는 drop만 가능)", c.Router.DefaultAction)
	}

	// 인터페이스 확인
	if c.Network.Interface != "" {
		if c.Network.Interface == "lo" || c.Network.Interface == "lo0" {
			// 루프백 인터페이스는 항상 허용
		} else {
			if _, err := net.InterfaceByName(c.Network.Interface); err != nil {
				fmt.Printf("네트워크 인터페이스 %s를 찾을 수 없음: %v\n", c.Network.Interface, err)
			}
		}
	}

	// 라우팅 규칙 검증
	for i, rule := range c.RoutingRules {
		if err := validateRoutingRule(rule); err != nil {
			return fmt.Errorf("라우팅 규칙 %d 검증 실패: %w", i+1, err)
		}
	}

	return nil
}

// validateRoutingRule은 라우팅 규칙의 유효성을 검사합니다
func validateRoutingRule(rule *RoutingRule) error {
	if rule.ID <= 0 {
		return fmt.Errorf("규칙 ID는 0보다 커야 함: %d", rule.ID)
	}

	if rule.Name == "" {
		return fmt.Errorf("규칙 이름이 필요합니다")
	}

	// IP 주소 검증
	if rule.SrcIP != "" {
		if _, _, err := net.ParseCIDR(rule.SrcIP); err != nil {
			if net.ParseIP(rule.SrcIP) == nil {
				return fmt.Errorf("잘못된 소스 IP 형식: %s", rule.SrcIP)
			}
		}
	}

	if rule.DstIP != "" {
		if _, _, err := net.ParseCIDR(rule.DstIP); err != nil {
			if net.ParseIP(rule.DstIP) == nil {
				return fmt.Errorf("잘못된 목적지 IP 형식: %s", rule.DstIP)
			}
		}
	}

	// 포트 검증
	if rule.SrcPort < 0 || rule.SrcPort > 65535 {
		return fmt.Errorf("잘못된 소스 포트 번호: %d", rule.SrcPort)
	}
	if rule.DstPort < 0 || rule.DstPort > 65535 {
		return fmt.Errorf("잘못된 목적지 포트 번호: %d", rule.DstPort)
	}

	// 프로토콜 검증
	if rule.Protocol != "" {
		validProtocols := map[string]bool{
			"tcp": true, "udp": true, "icmp": true,
		}
		if !validProtocols[rule.Protocol] {
			return fmt.Errorf("지원되지 않는 프로토콜: %s", rule.Protocol)
		}
	}

	// 액션 검증
	validActions := map[string]bool{
		"pass": true, "drop": true, "redirect": true,
	}
	if !validActions[rule.Action] {
		return fmt.Errorf("지원되지 않는 액션: %s", rule.Action)
	}

	// 우선순위 검증
	if rule.Priority < 0 || rule.Priority > 100 {
		return fmt.Errorf("우선순위는 0-100 범위여야 함: %d", rule.Priority)
	}

	return nil
}
