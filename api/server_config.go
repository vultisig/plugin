package api

// ServerConfig holds the configuration parameters for the server.
//
// Fields:
// - Host: The hostname or IP address where the server will run.
// - Port: The port number on which the server will listen for incoming requests.
// - EncryptionSecret: A secret key used for encrypting sensitive data.
// - Database: Configuration for the database connection, including:
//   - DSN: The Data Source Name (DSN) for connecting to the database.
type ServerConfig struct {
	Host             string `mapstructure:"host" json:"host,omitempty"`
	Port             int64  `mapstructure:"port" json:"port,omitempty"`
	EncryptionSecret string `mapstructure:"encryption_secret" json:"encryption_secret,omitempty"`
}
