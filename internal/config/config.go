package config

import (
	"fmt"
	"net"
	"time"

	"github.com/spf13/viper"
)

// Config는 라우터의 전체 설정을 담는 구조체입니다
type Config struct {
	Router  RouterConfig  `yaml:"router" mapstructure:"router"`
	Network NetworkConfig `yaml:"network" mapstructure:"network"`
	Logging LoggingConfig `yaml:"logging" mapstructure:"logging"`
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
	ID       int    `yaml:"id" mapstructure:"id"`
	Name     string `yaml:"name" mapstructure:"name"`
	SrcIP    string `yaml:"src_ip" mapstructure:"src_ip"`
	DstIP    string `yaml:"dst_ip" mapstructure:"dst_ip"`
	DstPort  int    `yaml:"dst_port" mapstructure:"dst_port"`
	Protocol string `yaml:"protocol" mapstructure:"protocol"`
	Action   string `yaml:"action" mapstructure:"action"`
	Priority int    `yaml:"priority" mapstructure:"priority"`
	Enabled  bool   `yaml:"enabled" mapstructure:"enabled"`
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
	viper.SetDefault("router.default_action", "pass")
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
		return fmt.Errorf("잘못된 기본 액션: '%s' (pass 또는 drop만 가능)", c.Router.DefaultAction)
	}

	// 인터페이스 확인
	if c.Network.Interface != "" {
		// TODO: 개발 중에는 lo, lo0 둘 다 허용
		if c.Network.Interface == "lo" || c.Network.Interface == "lo0" {
			return nil
		}

		if _, err := net.InterfaceByName(c.Network.Interface); err != nil {
			fmt.Printf("경고: 네트워크 인터페이스 '%s'를 찾을 수 없습니다: %v\n", c.Network.Interface, err)
			// TODO: 개발 중에는 에러로 처리하지 않음
		}
	}

	return nil
}
