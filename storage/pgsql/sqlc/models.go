// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0

package sqlc

import (
	"database/sql"
)

type DepName struct {
	Name                   string
	ConsumerKey            sql.NullString
	ConsumerSecret         sql.NullString
	AccessToken            sql.NullString
	AccessSecret           sql.NullString
	AccessTokenExpiry      sql.NullTime
	ConfigBaseUrl          sql.NullString
	TokenpkiCertPem        []byte
	TokenpkiKeyPem         []byte
	TokenpkiStagingCertPem []byte
	TokenpkiStagingKeyPem  []byte
	SyncerCursor           sql.NullString
	AssignerProfileUuid    sql.NullString
	AssignerProfileUuidAt  sql.NullTime
	CreatedAt              sql.NullTime
	UpdatedAt              sql.NullTime
}