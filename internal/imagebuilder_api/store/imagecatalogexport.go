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

// ImageCatalogExportStore is the store interface for ImageCatalogExport resources
type ImageCatalogExportStore interface {
	Create(ctx context.Context, orgId uuid.UUID, export *domain.ImageCatalogExport) (*domain.ImageCatalogExport, error)
	Get(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageCatalogExport, error)
	List(ctx context.Context, orgId uuid.UUID, listParams flightctlstore.ListParams) (*domain.ImageCatalogExportList, error)
	Delete(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageCatalogExport, error)
	// ListByImageDefinition returns all ImageCatalogExport resources referencing the given ImageDefinition name.
	ListByImageDefinition(ctx context.Context, orgId uuid.UUID, imageDefinitionName string) ([]domain.ImageCatalogExport, error)
	InitialMigration(ctx context.Context) error
}

// imageCatalogExportStore is the concrete implementation of ImageCatalogExportStore
type imageCatalogExportStore struct {
	db  *gorm.DB
	log logrus.FieldLogger
}

// NewImageCatalogExportStore creates a new ImageCatalogExport store
func NewImageCatalogExportStore(db *gorm.DB, log logrus.FieldLogger) ImageCatalogExportStore {
	return &imageCatalogExportStore{
		db:  db,
		log: log,
	}
}

// InitialMigration creates the image_catalog_exports table
func (s *imageCatalogExportStore) InitialMigration(ctx context.Context) error {
	return s.db.WithContext(ctx).AutoMigrate(&ImageCatalogExport{})
}

// Create creates a new ImageCatalogExport resource
func (s *imageCatalogExportStore) Create(ctx context.Context, orgId uuid.UUID, export *domain.ImageCatalogExport) (*domain.ImageCatalogExport, error) {
	if export == nil || export.Metadata.Name == nil {
		return nil, flterrors.ErrResourceNameIsNil
	}

	m, err := NewImageCatalogExportFromDomain(export)
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

// Get retrieves an ImageCatalogExport resource by name
func (s *imageCatalogExportStore) Get(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageCatalogExport, error) {
	m := &ImageCatalogExport{}
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

// List retrieves a list of ImageCatalogExport resources
func (s *imageCatalogExportStore) List(ctx context.Context, orgId uuid.UUID, listParams flightctlstore.ListParams) (*domain.ImageCatalogExportList, error) {
	var models []ImageCatalogExport
	var nextContinue *string
	var numRemaining *int64

	if len(listParams.SortColumns) == 0 {
		listParams.SortColumns = []flightctlstore.SortColumn{flightctlstore.SortByCreatedAt}
		sortDesc := flightctlstore.SortDesc
		listParams.SortOrder = &sortDesc
	}

	query, err := flightctlstore.ListQuery(&ImageCatalogExport{}).Build(ctx, s.db.WithContext(ctx), orgId, listParams)
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

	list, err := ImageCatalogExportsToDomain(models, nextContinue, numRemaining)
	if err != nil {
		return nil, err
	}
	return &list, nil
}

func (s *imageCatalogExportStore) calculateContinue(ctx context.Context, orgId uuid.UUID, models []ImageCatalogExport, listParams flightctlstore.ListParams) (*string, *int64) {
	lastItem := models[len(models)-1]
	continueValues := []string{lastItem.CreatedAt.Format(time.RFC3339Nano)}

	var numRemainingVal int64
	if listParams.Continue != nil {
		numRemainingVal = listParams.Continue.Count - int64(listParams.Limit)
		if numRemainingVal < 1 {
			numRemainingVal = 1
		}
	} else {
		countQuery, err := flightctlstore.ListQuery(&ImageCatalogExport{}).Build(ctx, s.db.WithContext(ctx), orgId, listParams)
		if err == nil {
			numRemainingVal = flightctlstore.CountRemainingItems(countQuery, continueValues, listParams)
		}
	}

	return flightctlstore.BuildContinueString(continueValues, numRemainingVal), &numRemainingVal
}

// Delete removes an ImageCatalogExport resource by name and returns the deleted resource.
// Delete is idempotent - returns (nil, nil) if the resource doesn't exist.
func (s *imageCatalogExportStore) Delete(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageCatalogExport, error) {
	m := &ImageCatalogExport{}
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

	result = s.db.WithContext(ctx).Unscoped().Where("org_id = ? AND name = ?", orgId, name).Delete(&ImageCatalogExport{})
	if result.Error != nil {
		return nil, flightctlstore.ErrorFromGormError(result.Error)
	}

	return domainResource, nil
}

// ListByImageDefinition returns all ImageCatalogExport resources referencing the given ImageDefinition.
func (s *imageCatalogExportStore) ListByImageDefinition(ctx context.Context, orgId uuid.UUID, imageDefinitionName string) ([]domain.ImageCatalogExport, error) {
	var models []ImageCatalogExport
	err := s.db.WithContext(ctx).
		Where("org_id = ? AND spec->>'imageDefinitionRef' = ?", orgId, imageDefinitionName).
		Find(&models).Error
	if err != nil {
		return nil, flightctlstore.ErrorFromGormError(err)
	}

	result := make([]domain.ImageCatalogExport, 0, len(models))
	for _, m := range models {
		d, err := m.ToDomain()
		if err != nil {
			return nil, err
		}
		result = append(result, *d)
	}
	return result, nil
}
