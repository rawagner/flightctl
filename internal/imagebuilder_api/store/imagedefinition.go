package store

import (
	"context"
	"errors"
	"time"

	"github.com/flightctl/flightctl/internal/flterrors"
	"github.com/flightctl/flightctl/internal/imagebuilder_api/domain"
	flightctlstore "github.com/flightctl/flightctl/internal/store"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// ImageDefinitionStore is the store interface for ImageDefinition resources
type ImageDefinitionStore interface {
	Create(ctx context.Context, orgId uuid.UUID, imageDef *domain.ImageDefinition) (*domain.ImageDefinition, error)
	Get(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageDefinition, error)
	List(ctx context.Context, orgId uuid.UUID, listParams flightctlstore.ListParams) (*domain.ImageDefinitionList, error)
	Delete(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageDefinition, error)
	// LatestCompletedBuildVersion returns the resolvedVersion from the latest completed ImageBuild
	// that references this ImageDefinition, or empty string if none exists.
	LatestCompletedBuildVersion(ctx context.Context, orgId uuid.UUID, imageDefinitionName string) (string, error)
	InitialMigration(ctx context.Context) error
}

// imageDefinitionStore is the concrete implementation of ImageDefinitionStore
type imageDefinitionStore struct {
	db  *gorm.DB
	log logrus.FieldLogger
}

// NewImageDefinitionStore creates a new ImageDefinition store
func NewImageDefinitionStore(db *gorm.DB, log logrus.FieldLogger) ImageDefinitionStore {
	return &imageDefinitionStore{
		db:  db,
		log: log,
	}
}

// InitialMigration creates the image_definitions table
func (s *imageDefinitionStore) InitialMigration(ctx context.Context) error {
	return s.db.WithContext(ctx).AutoMigrate(&ImageDefinition{})
}

// Create creates a new ImageDefinition resource
func (s *imageDefinitionStore) Create(ctx context.Context, orgId uuid.UUID, imageDef *domain.ImageDefinition) (*domain.ImageDefinition, error) {
	if imageDef == nil || imageDef.Metadata.Name == nil {
		return nil, flterrors.ErrResourceNameIsNil
	}

	m, err := NewImageDefinitionFromDomain(imageDef)
	if err != nil {
		return nil, err
	}
	m.OrgID = orgId
	m.Generation = lo.ToPtr(int64(1))
	m.ResourceVersion = lo.ToPtr(int64(1))

	db := getDB(ctx, s.db)
	result := db.WithContext(ctx).Create(m)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			return nil, flterrors.ErrDuplicateName
		}
		return nil, result.Error
	}

	return m.ToDomain()
}

// Get retrieves an ImageDefinition resource by name
func (s *imageDefinitionStore) Get(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageDefinition, error) {
	m := &ImageDefinition{}
	db := getDB(ctx, s.db)
	result := db.WithContext(ctx).Where("org_id = ? AND name = ?", orgId, name).First(m)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, flterrors.ErrResourceNotFound
		}
		return nil, result.Error
	}
	return m.ToDomain()
}

// List retrieves a list of ImageDefinition resources
func (s *imageDefinitionStore) List(ctx context.Context, orgId uuid.UUID, listParams flightctlstore.ListParams) (*domain.ImageDefinitionList, error) {
	var models []ImageDefinition
	var nextContinue *string
	var numRemaining *int64

	if len(listParams.SortColumns) == 0 {
		listParams.SortColumns = []flightctlstore.SortColumn{flightctlstore.SortByCreatedAt}
		sortDesc := flightctlstore.SortDesc
		listParams.SortOrder = &sortDesc
	}

	query, err := flightctlstore.ListQuery(&ImageDefinition{}).Build(ctx, s.db.WithContext(ctx), orgId, listParams)
	if err != nil {
		return nil, err
	}

	if listParams.Limit > 0 {
		query = flightctlstore.AddPaginationToQuery(query, listParams.Limit+1, listParams.Continue, listParams)
	}

	if err := query.Find(&models).Error; err != nil {
		return nil, flightctlstore.ErrorFromGormError(err)
	}

	if listParams.Limit > 0 && len(models) > listParams.Limit {
		nextContinue, numRemaining = s.calculateContinue(ctx, orgId, models, listParams)
		models = models[:len(models)-1]
	}

	list, err := ImageDefinitionsToDomain(models, nextContinue, numRemaining)
	if err != nil {
		return nil, err
	}
	return &list, nil
}

func (s *imageDefinitionStore) calculateContinue(ctx context.Context, orgId uuid.UUID, models []ImageDefinition, listParams flightctlstore.ListParams) (*string, *int64) {
	lastItem := models[len(models)-1]
	continueValues := []string{lastItem.CreatedAt.Format(time.RFC3339Nano)}

	var numRemainingVal int64
	if listParams.Continue != nil {
		numRemainingVal = listParams.Continue.Count - int64(listParams.Limit)
		if numRemainingVal < 1 {
			numRemainingVal = 1
		}
	} else {
		countQuery, err := flightctlstore.ListQuery(&ImageDefinition{}).Build(ctx, s.db.WithContext(ctx), orgId, listParams)
		if err == nil {
			numRemainingVal = flightctlstore.CountRemainingItems(countQuery, continueValues, listParams)
		}
	}

	return flightctlstore.BuildContinueString(continueValues, numRemainingVal), &numRemainingVal
}

// Delete removes an ImageDefinition resource by name and returns the deleted resource.
// Delete is idempotent - returns (nil, nil) if the resource doesn't exist.
func (s *imageDefinitionStore) Delete(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageDefinition, error) {
	m := &ImageDefinition{}
	result := s.db.WithContext(ctx).Where("org_id = ? AND name = ?", orgId, name).First(m)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, flightctlstore.ErrorFromGormError(result.Error)
	}

	domainResource, err := m.ToDomain()
	if err != nil {
		return nil, err
	}

	result = s.db.WithContext(ctx).Unscoped().Where("org_id = ? AND name = ?", orgId, name).Delete(&ImageDefinition{})
	if result.Error != nil {
		return nil, flightctlstore.ErrorFromGormError(result.Error)
	}

	return domainResource, nil
}

// LatestCompletedBuildVersion returns the resolvedVersion from the latest completed ImageBuild
// referencing the given ImageDefinition. Returns empty string if no completed build is found.
func (s *imageDefinitionStore) LatestCompletedBuildVersion(ctx context.Context, orgId uuid.UUID, imageDefinitionName string) (string, error) {
	var build ImageBuild
	result := s.db.WithContext(ctx).
		Where("org_id = ?", orgId).
		Where("spec->>'imageDefinitionRef' = ?", imageDefinitionName).
		Where(`(SELECT elem->>'reason' FROM jsonb_array_elements(COALESCE(status, '{}'::jsonb)->'conditions') AS elem WHERE elem->>'type' = 'Ready' LIMIT 1) = 'Completed'`).
		Order("created_at DESC").
		First(&build)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", result.Error
	}

	if build.Status == nil {
		return "", nil
	}
	return lo.FromPtrOr(build.Status.Data.ResolvedVersion, ""), nil
}
