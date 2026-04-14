package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/flightctl/flightctl/internal/flterrors"
	"github.com/flightctl/flightctl/internal/imagebuilder_api/domain"
	"github.com/flightctl/flightctl/internal/imagebuilder_api/store"
	"github.com/flightctl/flightctl/internal/store/selector"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
)

// ImageCatalogExportService handles business logic for ImageCatalogExport resources
type ImageCatalogExportService interface {
	Create(ctx context.Context, orgId uuid.UUID, export domain.ImageCatalogExport) (*domain.ImageCatalogExport, domain.Status)
	Get(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageCatalogExport, domain.Status)
	List(ctx context.Context, orgId uuid.UUID, params domain.ListImageCatalogExportsParams) (*domain.ImageCatalogExportList, domain.Status)
	Delete(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageCatalogExport, domain.Status)
	// ListByImageDefinition returns all exports referencing the given ImageDefinition name.
	ListByImageDefinition(ctx context.Context, orgId uuid.UUID, imageDefinitionName string) ([]domain.ImageCatalogExport, error)
}

// imageCatalogExportService is the concrete implementation of ImageCatalogExportService
type imageCatalogExportService struct {
	store                store.ImageCatalogExportStore
	imageDefinitionStore store.ImageDefinitionStore
	log                  logrus.FieldLogger
}

// NewImageCatalogExportService creates a new ImageCatalogExportService
func NewImageCatalogExportService(s store.ImageCatalogExportStore, imageDefinitionStore store.ImageDefinitionStore, log logrus.FieldLogger) ImageCatalogExportService {
	return &imageCatalogExportService{
		store:                s,
		imageDefinitionStore: imageDefinitionStore,
		log:                  log,
	}
}

func (s *imageCatalogExportService) Create(ctx context.Context, orgId uuid.UUID, export domain.ImageCatalogExport) (*domain.ImageCatalogExport, domain.Status) {
	NilOutManagedObjectMetaProperties(&export.Metadata)

	if errs, internalErr := s.validate(ctx, orgId, &export); internalErr != nil {
		return nil, StatusInternalServerError(internalErr.Error())
	} else if len(errs) > 0 {
		return nil, StatusBadRequest(errors.Join(errs...).Error())
	}

	result, err := s.store.Create(ctx, orgId, &export)
	return result, StoreErrorToApiStatus(err, true, string(domain.ResourceKindImageCatalogExport), export.Metadata.Name)
}

func (s *imageCatalogExportService) Get(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageCatalogExport, domain.Status) {
	result, err := s.store.Get(ctx, orgId, name)
	return result, StoreErrorToApiStatus(err, false, string(domain.ResourceKindImageCatalogExport), &name)
}

func (s *imageCatalogExportService) List(ctx context.Context, orgId uuid.UUID, params domain.ListImageCatalogExportsParams) (*domain.ImageCatalogExportList, domain.Status) {
	listParams, status := prepareListParams(params.Continue, params.LabelSelector, params.FieldSelector, params.Limit)
	if !IsStatusOK(status) {
		return nil, status
	}

	result, err := s.store.List(ctx, orgId, *listParams)
	if err == nil {
		return result, StatusOK()
	}

	var se *selector.SelectorError
	switch {
	case selector.AsSelectorError(err, &se):
		return nil, StatusBadRequest(se.Error())
	default:
		return nil, StatusInternalServerError(err.Error())
	}
}

func (s *imageCatalogExportService) Delete(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageCatalogExport, domain.Status) {
	_, err := s.store.Get(ctx, orgId, name)
	if err != nil {
		if errors.Is(err, flterrors.ErrResourceNotFound) {
			return nil, StatusOK()
		}
		return nil, StoreErrorToApiStatus(err, false, string(domain.ResourceKindImageCatalogExport), &name)
	}

	result, err := s.store.Delete(ctx, orgId, name)
	return result, StoreErrorToApiStatus(err, false, string(domain.ResourceKindImageCatalogExport), &name)
}

func (s *imageCatalogExportService) ListByImageDefinition(ctx context.Context, orgId uuid.UUID, imageDefinitionName string) ([]domain.ImageCatalogExport, error) {
	return s.store.ListByImageDefinition(ctx, orgId, imageDefinitionName)
}

// validate performs validation on an ImageCatalogExport resource
func (s *imageCatalogExportService) validate(ctx context.Context, orgId uuid.UUID, export *domain.ImageCatalogExport) ([]error, error) {
	var errs []error

	if lo.FromPtr(export.Metadata.Name) == "" {
		errs = append(errs, errors.New("metadata.name is required"))
	}

	if export.Spec.ImageDefinitionRef == "" {
		errs = append(errs, errors.New("spec.imageDefinitionRef is required"))
	} else {
		_, err := s.imageDefinitionStore.Get(ctx, orgId, export.Spec.ImageDefinitionRef)
		if errors.Is(err, flterrors.ErrResourceNotFound) {
			errs = append(errs, fmt.Errorf("spec.imageDefinitionRef: ImageDefinition %q not found", export.Spec.ImageDefinitionRef))
		} else if err != nil {
			return nil, fmt.Errorf("failed to get ImageDefinition %q: %w", export.Spec.ImageDefinitionRef, err)
		}
	}

	if export.Spec.CatalogRef == "" {
		errs = append(errs, errors.New("spec.catalogRef is required"))
	}

	return errs, nil
}
