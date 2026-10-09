package dbfs

import (
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/gofrs/uuid"
)

func TestFindVersionSessionReplacement(t *testing.T) {
	oldEntity := &ent.Entity{ID: 10, Type: int(types.EntityTypeVersion)}
	newEntity := &ent.Entity{ID: 11, Type: int(types.EntityTypeVersion)}
	file := &File{Model: &ent.File{Edges: ent.FileEdges{
		Metadata: []*ent.Metadata{
			{Name: MetadataVersionSessionID, Value: "session-a"},
			{Name: MetadataVersionSessionEntity, Value: "10"},
		},
		Entities: []*ent.Entity{newEntity, oldEntity},
	}}}

	if got := findVersionSessionReplacement(file, "session-a", newEntity.ID); got != oldEntity {
		t.Fatalf("expected entity %d, got %#v", oldEntity.ID, got)
	}
	if got := findVersionSessionReplacement(file, "session-b", newEntity.ID); got != nil {
		t.Fatalf("new session must not replace an old session entity: %#v", got)
	}
}

func TestFindVersionSessionReplacementRejectsIncompleteEntity(t *testing.T) {
	uploadID := uuid.Must(uuid.NewV4())
	incomplete := &ent.Entity{
		ID:              10,
		Type:            int(types.EntityTypeVersion),
		UploadSessionID: &uploadID,
	}
	file := &File{Model: &ent.File{Edges: ent.FileEdges{
		Metadata: []*ent.Metadata{
			{Name: MetadataVersionSessionID, Value: "session-a"},
			{Name: MetadataVersionSessionEntity, Value: "10"},
		},
		Entities: []*ent.Entity{incomplete},
	}}}

	if got := findVersionSessionReplacement(file, "session-a", 11); got != nil {
		t.Fatalf("incomplete upload entity must not be replaced: %#v", got)
	}
}
