package firestore

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/googleapi"

	"github.com/micromdm/nanodep/client"
)

const (
	CollectionName  = "dep_names"
	timestampFormat = "2006-01-02T15:04:05Z"
)

// FirestoreStorage provides an implementation of storage using Firestore.
type FirestoreStorage struct {
	client *firestore.Client
}

type config struct {
	driver string
	dsn    string
	db     string
}

// Option allows configuring a Firestore Storage.
type Option func(*config)

// WithDSN sets the storage Firestore data source name.
func WithDSN(dsn string) Option {
	return func(c *config) {
		c.dsn = dsn
	}
}

// WithDB sets the storage Firestore database name.
func WithDB(db string) Option {
	return func(c *config) {
		c.db = db
	}
}

// New creates a new FirestoreStorage backend and initializes the Firestore client.
func New(opts ...Option) (*FirestoreStorage, error) {
	var client *firestore.Client
	var err error

	cfg := &config{driver: "firestore"}

	// Apply options to configure the Firestore client
	for _, opt := range opts {
		opt(cfg)
	}

	ctx := context.Background()

	// Initialize Firestore client based on the provided options
	if cfg.db != "" {
		client, err = firestore.NewClientWithDatabase(ctx, cfg.dsn, cfg.db)
	} else {
		client, err = firestore.NewClient(ctx, cfg.dsn)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create Firestore client: %w", err)
	}

	return &FirestoreStorage{client: client}, nil
}

// isNotFoundError checks if the given error is a "not found" error from the Firestore API.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if apiErr, ok := err.(*googleapi.Error); ok && apiErr.Code == http.StatusNotFound {
		return true
	}
	return false
}

// RetrieveAuthTokens reads the OAuth tokens from Firestore for the given name.
func (s *FirestoreStorage) RetrieveAuthTokens(ctx context.Context, name string) (*client.OAuth1Tokens, error) {
	if s.client == nil {
		return nil, fmt.Errorf("Firestore client is nil")
	}

	// Fetch the document from Firestore
	doc, err := s.client.Collection(CollectionName).Doc(name).Get(ctx)
	if err != nil {
		if isNotFoundError(err) {
			return nil, fmt.Errorf("auth tokens not found: %w", err)
		}
		return nil, fmt.Errorf("failed to retrieve auth tokens: %w", err)
	}

	// Parse and return the tokens
	data := doc.Data()
	accessTokenExpiryTime, err := time.Parse(timestampFormat, data["access_token_expiry"].(string))
	if err != nil {
		return nil, fmt.Errorf("failed to parse access token expiry time: %w", err)
	}

	return &client.OAuth1Tokens{
		ConsumerKey:       data["consumer_key"].(string),
		ConsumerSecret:    data["consumer_secret"].(string),
		AccessToken:       data["access_token"].(string),
		AccessSecret:      data["access_secret"].(string),
		AccessTokenExpiry: accessTokenExpiryTime,
	}, nil
}

// StoreAuthTokens saves the OAuth tokens to Firestore for the given name.
func (s *FirestoreStorage) StoreAuthTokens(ctx context.Context, name string, tokens *client.OAuth1Tokens) error {
	if s.client == nil {
		return fmt.Errorf("Firestore client is nil")
	}

	// Convert tokens struct to a map and store it in Firestore
	tokensMap, err := structToMap(tokens)
	if err != nil {
		return fmt.Errorf("failed to convert tokens to map: %w", err)
	}

	_, err = s.client.Collection(CollectionName).Doc(name).Set(ctx, tokensMap, firestore.MergeAll)
	if err != nil {
		return fmt.Errorf("failed to store auth tokens: %w", err)
	}
	return nil
}

// Helper function to convert struct to map for Firestore operations.
func structToMap(v interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// RetrieveConfig reads the DEP config from Firestore for the given name.
func (s *FirestoreStorage) RetrieveConfig(ctx context.Context, name string) (*client.Config, error) {
	if s.client == nil {
		return nil, fmt.Errorf("Firestore client is nil")
	}

	// Fetch the document from Firestore
	doc, err := s.client.Collection(CollectionName).Doc(name).Get(ctx)
	if err != nil {
		if isNotFoundError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to retrieve config: %w", err)
	}

	// Check if the "config_base_url" field exists
	data := doc.Data()
	if _, ok := data["config_base_url"]; !ok {
		return nil, nil
	}

	return &client.Config{
		BaseURL: data["config_base_url"].(string),
	}, nil
}

// StoreConfig saves the DEP config to Firestore for the given name.
func (s *FirestoreStorage) StoreConfig(ctx context.Context, name string, config *client.Config) error {
	if s.client == nil {
		return fmt.Errorf("Firestore client is nil")
	}

	// Convert config struct to a map and store it in Firestore
	data := map[string]interface{}{
		"name":            name,
		"config_base_url": config.BaseURL,
	}

	_, err := s.client.Collection(CollectionName).Doc(name).Set(ctx, data, firestore.MergeAll)
	if err != nil {
		return fmt.Errorf("failed to store config: %w", err)
	}
	return nil
}

// RetrieveAssignerProfile reads the assigner profile UUID and its timestamp from Firestore.
func (s *FirestoreStorage) RetrieveAssignerProfile(ctx context.Context, name string) (profileUUID string, modTime time.Time, err error) {
	if s.client == nil {
		return "", time.Time{}, fmt.Errorf("Firestore client is nil")
	}

	// Fetch the document from Firestore
	doc, err := s.client.Collection(CollectionName).Doc(name).Get(ctx)
	if err != nil {
		if isNotFoundError(err) {
			return "", time.Time{}, nil
		}
		return "", time.Time{}, fmt.Errorf("failed to retrieve assigner profile: %w", err)
	}

	data := doc.Data()

	// Extract fields from the document data
	if _, ok := data["assigner_profile_uuid"]; !ok {
		profileUUID = data["assigner_profile_uuid"].(string)
	}
	if _, ok := data["assigner_profile_uuid_at"]; !ok {
		modTime, err = time.Parse(timestampFormat, data["assigner_profile_uuid"].(string))
	}
	return
}

// StoreAssignerProfile saves the assigner profile UUID and its timestamp to Firestore.
func (s *FirestoreStorage) StoreAssignerProfile(ctx context.Context, name string, profileUUID string) error {
	if s.client == nil {
		return fmt.Errorf("Firestore client is nil")
	}

	// Prepare data and store it in Firestore
	data := map[string]interface{}{
		"name":                     name,
		"assigner_profile_uuid":    profileUUID,
		"assigner_profile_uuid_at": time.Now(),
	}

	_, err := s.client.Collection(CollectionName).Doc(name).Set(ctx, data, firestore.MergeAll)
	if err != nil {
		return fmt.Errorf("failed to store assigner profile: %w", err)
	}
	return nil
}

// RetrieveCursor reads the cursor value from Firestore for the given name.
func (s *FirestoreStorage) RetrieveCursor(ctx context.Context, name string) (string, error) {
	if s.client == nil {
		return "", fmt.Errorf("Firestore client is nil")
	}

	// Fetch the document from Firestore
	doc, err := s.client.Collection(CollectionName).Doc(name).Get(ctx)
	if err != nil {
		if isNotFoundError(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to retrieve cursor: %w", err)
	}

	data := doc.Data()

	// Check if the cursor field exists
	cursor, ok := data["syncer_cursor"].(string)
	if !ok {
		return "", nil
	}

	return cursor, nil
}

// StoreCursor saves the cursor value to Firestore for the given name.
func (s *FirestoreStorage) StoreCursor(ctx context.Context, name string, cursor string) error {
	if s.client == nil {
		return fmt.Errorf("Firestore client is nil")
	}

	// Prepare data and store it in Firestore
	data := map[string]interface{}{
		"name":          name,
		"syncer_cursor": cursor,
	}

	_, err := s.client.Collection(CollectionName).Doc(name).Set(ctx, data, firestore.MergeAll)
	if err != nil {
		return fmt.Errorf("failed to store cursor: %w", err)
	}
	return nil
}

// StoreTokenPKI saves the PEM bytes for the token exchange certificate and key to Firestore.
func (s *FirestoreStorage) StoreTokenPKI(ctx context.Context, name string, pemCert []byte, pemKey []byte) error {
	if s.client == nil {
		return fmt.Errorf("Firestore client is nil")
	}

	// Prepare data and store it in Firestore
	data := map[string]interface{}{
		"name":                      name,
		"tokenpki_staging_cert_pem": string(pemCert),
		"tokenpki_staging_key_pem":  string(pemKey),
	}

	_, err := s.client.Collection(CollectionName).Doc(name).Set(ctx, data, firestore.MergeAll)
	if err != nil {
		return fmt.Errorf("failed to store token PKI: %w", err)
	}
	return nil
}

// UpstageTokenPKI copies the staging PKI certificate and key to the current PKI certificate and key.
func (s *FirestoreStorage) UpstageTokenPKI(ctx context.Context, name string) error {
	if s.client == nil {
		return fmt.Errorf("Firestore client is nil")
	}

	// Retrieve the staging PKI from Firestore
	stagingDocRef := s.client.Collection(CollectionName).Doc(name)
	stagingDoc, err := stagingDocRef.Get(ctx)
	if err != nil {
		if isNotFoundError(err) {
			return fmt.Errorf("staging token PKI not found: %w", err)
		}
		return fmt.Errorf("failed to retrieve staging token PKI: %w", err)
	}

	// Decode the staging PKI document
	var stagingData struct {
		Cert string `firestore:"tokenpki_staging_cert_pem"`
		Key  string `firestore:"tokenpki_staging_key_pem"`
	}
	if err := stagingDoc.DataTo(&stagingData); err != nil {
		return fmt.Errorf("failed to decode staging token PKI: %w", err)
	}

	// Prepare the map to store the current PKI data
	dataMap := map[string]interface{}{
		"tokenpki_staging_cert_pem": stagingData.Cert,
		"tokenpki_staging_key_pem":  stagingData.Key,
	}

	// Update the current PKI with the staging data
	currentDocRef := s.client.Collection(CollectionName).Doc(name)
	_, err = currentDocRef.Set(ctx, dataMap, firestore.MergeAll)
	if err != nil {
		return fmt.Errorf("failed to update current token PKI: %w", err)
	}

	return nil
}

// RetrieveTokenPKI reads the PEM bytes for the token exchange certificate and key from Firestore.
func (s *FirestoreStorage) RetrieveTokenPKI(ctx context.Context, name string) ([]byte, []byte, error) {
	if s.client == nil {
		return nil, nil, fmt.Errorf("Firestore client is nil")
	}

	// Fetch the document from Firestore
	doc, err := s.client.Collection(CollectionName).Doc(name).Get(ctx)
	if err != nil {
		if isNotFoundError(err) {
			return nil, nil, fmt.Errorf("token PKI not found: %w", err)
		}
		return nil, nil, fmt.Errorf("failed to retrieve token PKI: %w", err)
	}

	// Decode the document data
	var data struct {
		Cert string `firestore:"tokenpki_staging_cert_pem"`
		Key  string `firestore:"tokenpki_staging_key_pem"`
	}
	if err := doc.DataTo(&data); err != nil {
		return nil, nil, fmt.Errorf("failed to decode token PKI: %w", err)
	}

	return []byte(data.Cert), []byte(data.Key), nil
}

// RetrieveStagingTokenPKI reads and returns the PEM bytes for the staged DEP token exchange certificate and private key.
func (s *FirestoreStorage) RetrieveStagingTokenPKI(ctx context.Context, name string) ([]byte, []byte, error) {
	if s.client == nil {
		return nil, nil, fmt.Errorf("Firestore client is nil")
	}

	// Fetch the document from Firestore
	doc, err := s.client.Collection(CollectionName).Doc(name).Get(ctx)
	if err != nil {
		if isNotFoundError(err) {
			return nil, nil, fmt.Errorf("staging token PKI not found: %w", err)
		}
		return nil, nil, fmt.Errorf("failed to retrieve staging token PKI: %w", err)
	}

	// Decode the document data
	var data struct {
		TokenpkiStagingCertPem string `firestore:"tokenpki_staging_cert_pem"`
		TokenpkiStagingKeyPem  string `firestore:"tokenpki_staging_key_pem"`
	}
	if err := doc.DataTo(&data); err != nil {
		return nil, nil, fmt.Errorf("failed to decode staging token PKI: %w", err)
	}

	return []byte(data.TokenpkiStagingCertPem), []byte(data.TokenpkiStagingKeyPem), nil
}

// RetrieveCurrentTokenPKI reads and returns the PEM bytes for the current token exchange certificate and key.
func (s *FirestoreStorage) RetrieveCurrentTokenPKI(ctx context.Context, name string) ([]byte, []byte, error) {
	if s.client == nil {
		return nil, nil, fmt.Errorf("Firestore client is nil")
	}

	// Fetch the document from Firestore
	doc, err := s.client.Collection(CollectionName).Doc(name).Get(ctx)
	if err != nil {
		if isNotFoundError(err) {
			return nil, nil, fmt.Errorf("current token PKI not found: %w", err)
		}
		return nil, nil, fmt.Errorf("failed to retrieve current token PKI: %w", err)
	}

	// Decode the document data
	var data struct {
		TokenpkiCertPem string `firestore:"tokenpki_cert_pem"`
		TokenpkiKeyPem  string `firestore:"tokenpki_key_pem"`
	}
	if err := doc.DataTo(&data); err != nil {
		return nil, nil, fmt.Errorf("failed to decode current token PKI: %w", err)
	}

	return []byte(data.TokenpkiCertPem), []byte(data.TokenpkiKeyPem), nil
}
