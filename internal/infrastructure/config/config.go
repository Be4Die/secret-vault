package config

import (
	"fmt"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env           string `env:"ENV"            env-default:"dev"`
	Port          int    `env:"PORT"           env-default:"8080"`
	DatabasePath  string `env:"DATABASE_PATH"  env-default:"./data/vault.db"`
	SessionSecret string `env:"SESSION_SECRET" env-required:"true"`
}

func Load() (*Config, error) {
	var cfg Config
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	return &cfg, nil
}
