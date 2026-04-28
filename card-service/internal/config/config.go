package config

type Config struct {
	HTTPPort int        `yaml:"http_port"`
	GRPCPort int        `yaml:"grpc_port"`
	DB       DBConfig   `yaml:"db"`
	JWT      JWTConfig  `yaml:"jwt"`
}

type DBConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Name     string `yaml:"name"`
	SSLMode  string `yaml:"sslmode"`
}

type JWTConfig struct {
	SigningMethod string   `yaml:"signing_method"`
	Issuer        string   `yaml:"issuer"`
	Audience      []string `yaml:"audience"`
	KeyFilePath   string   `yaml:"key_file_path"`
}
