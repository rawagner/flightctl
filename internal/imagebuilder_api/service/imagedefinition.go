package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/flightctl/flightctl/internal/flterrors"
	"github.com/flightctl/flightctl/internal/imagebuilder_api/domain"
	"github.com/flightctl/flightctl/internal/imagebuilder_api/store"
	"github.com/flightctl/flightctl/internal/store/selector"
	mainstore "github.com/flightctl/flightctl/internal/store"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
)

// ImageDefinitionService handles business logic for ImageDefinition resources
type ImageDefinitionService interface {
	Create(ctx context.Context, orgId uuid.UUID, imageDef domain.ImageDefinition) (*domain.ImageDefinition, domain.Status)
	Get(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageDefinition, domain.Status)
	List(ctx context.Context, orgId uuid.UUID, params domain.ListImageDefinitionsParams) (*domain.ImageDefinitionList, domain.Status)
	Delete(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageDefinition, domain.Status)
	// NextVersion computes the next version tag for a definition-mode ImageBuild.
	// It reads the latest completed build's resolvedVersion and increments the patch component.
	NextVersion(ctx context.Context, orgId uuid.UUID, imageDefinitionName string, versionPattern string) (string, error)
}

// imageDefinitionService is the concrete implementation of ImageDefinitionService
type imageDefinitionService struct {
	store            store.ImageDefinitionStore
	repositoryStore  mainstore.Repository
	log              logrus.FieldLogger
}

// NewImageDefinitionService creates a new ImageDefinitionService
func NewImageDefinitionService(s store.ImageDefinitionStore, repositoryStore mainstore.Repository, log logrus.FieldLogger) ImageDefinitionService {
	return &imageDefinitionService{
		store:           s,
		repositoryStore: repositoryStore,
		log:             log,
	}
}

func (s *imageDefinitionService) Create(ctx context.Context, orgId uuid.UUID, imageDef domain.ImageDefinition) (*domain.ImageDefinition, domain.Status) {
	NilOutManagedObjectMetaProperties(&imageDef.Metadata)

	if errs, internalErr := s.validate(ctx, orgId, &imageDef); internalErr != nil {
		return nil, StatusInternalServerError(internalErr.Error())
	} else if len(errs) > 0 {
		return nil, StatusBadRequest(errors.Join(errs...).Error())
	}

	result, err := s.store.Create(ctx, orgId, &imageDef)
	return result, StoreErrorToApiStatus(err, true, string(domain.ResourceKindImageDefinition), imageDef.Metadata.Name)
}

func (s *imageDefinitionService) Get(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageDefinition, domain.Status) {
	result, err := s.store.Get(ctx, orgId, name)
	return result, StoreErrorToApiStatus(err, false, string(domain.ResourceKindImageDefinition), &name)
}

func (s *imageDefinitionService) List(ctx context.Context, orgId uuid.UUID, params domain.ListImageDefinitionsParams) (*domain.ImageDefinitionList, domain.Status) {
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

func (s *imageDefinitionService) Delete(ctx context.Context, orgId uuid.UUID, name string) (*domain.ImageDefinition, domain.Status) {
	_, err := s.store.Get(ctx, orgId, name)
	if err != nil {
		if errors.Is(err, flterrors.ErrResourceNotFound) {
			return nil, StatusOK()
		}
		return nil, StoreErrorToApiStatus(err, false, string(domain.ResourceKindImageDefinition), &name)
	}

	result, err := s.store.Delete(ctx, orgId, name)
	return result, StoreErrorToApiStatus(err, false, string(domain.ResourceKindImageDefinition), &name)
}

// NextVersion computes the next version for a definition-mode build.
// The versionPattern is in the form "MAJOR.MINOR.x" (e.g. "1.0.x").
// It queries the store for the latest completed build's resolvedVersion and increments the patch.
func (s *imageDefinitionService) NextVersion(ctx context.Context, orgId uuid.UUID, imageDefinitionName string, versionPattern string) (string, error) {
	lastVersion, err := s.store.LatestCompletedBuildVersion(ctx, orgId, imageDefinitionName)
	if err != nil {
		return "", fmt.Errorf("failed to query latest completed build version: %w", err)
	}
	return NextVersion(versionPattern, lastVersion)
}

// NextVersion computes the next semver from a pattern and the last known version.
// Pattern must be "MAJOR.MINOR.x". If lastVersion is empty, returns the pattern with x=0.
func NextVersion(pattern, lastVersion string) (string, error) {
	parts := strings.Split(pattern, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("version pattern %q must have exactly 3 components (e.g. 1.0.x)", pattern)
	}
	if parts[2] != "x" {
		return "", fmt.Errorf("version pattern %q must end with 'x' as the patch component (e.g. 1.0.x)", pattern)
	}
	major := parts[0]
	minor := parts[1]

	if lastVersion == "" {
		return fmt.Sprintf("%s.%s.0", major, minor), nil
	}

	lastParts := strings.Split(lastVersion, ".")
	if len(lastParts) != 3 {
		return "", fmt.Errorf("last version %q is not a valid semver (expected 3 components)", lastVersion)
	}

	patch, err := strconv.Atoi(lastParts[2])
	if err != nil {
		return "", fmt.Errorf("patch component %q in last version %q is not an integer: %w", lastParts[2], lastVersion, err)
	}

	return fmt.Sprintf("%s.%s.%d", major, minor, patch+1), nil
}

// validate performs validation on an ImageDefinition resource
func (s *imageDefinitionService) validate(ctx context.Context, orgId uuid.UUID, imageDef *domain.ImageDefinition) ([]error, error) {
	var errs []error

	if lo.FromPtr(imageDef.Metadata.Name) == "" {
		errs = append(errs, errors.New("metadata.name is required"))
	}

	if imageDef.Spec.Version == "" {
		errs = append(errs, errors.New("spec.version is required"))
	} else {
		parts := strings.Split(imageDef.Spec.Version, ".")
		if len(parts) != 3 || parts[2] != "x" {
			errs = append(errs, fmt.Errorf("spec.version %q must be in the form MAJOR.MINOR.x (e.g. 1.0.x)", imageDef.Spec.Version))
		}
	}

	if imageDef.Spec.Source.Repository == "" {
		errs = append(errs, errors.New("spec.source.repository is required"))
	} else {
		repo, err := s.repositoryStore.Get(ctx, orgId, imageDef.Spec.Source.Repository)
		if errors.Is(err, flterrors.ErrResourceNotFound) {
			errs = append(errs, fmt.Errorf("spec.source.repository: Repository %q not found", imageDef.Spec.Source.Repository))
		} else if err != nil {
			return nil, fmt.Errorf("failed to get source repository %q: %w", imageDef.Spec.Source.Repository, err)
		} else {
			specType, err := repo.Spec.Discriminator()
			if err != nil {
				return nil, fmt.Errorf("failed to get source repository spec type: %w", err)
			}
			if specType != string(domain.RepoSpecTypeOci) {
				errs = append(errs, fmt.Errorf("spec.source.repository: Repository %q must be of type 'oci'", imageDef.Spec.Source.Repository))
			}
		}
	}
	errs = append(errs, ValidateImageName(&imageDef.Spec.Source.ImageName, "spec.source.imageName")...)
	errs = append(errs, ValidateImageTag(&imageDef.Spec.Source.ImageTag, "spec.source.imageTag")...)

	if imageDef.Spec.Destination.Repository == "" {
		errs = append(errs, errors.New("spec.destination.repository is required"))
	} else {
		repo, err := s.repositoryStore.Get(ctx, orgId, imageDef.Spec.Destination.Repository)
		if errors.Is(err, flterrors.ErrResourceNotFound) {
			errs = append(errs, fmt.Errorf("spec.destination.repository: Repository %q not found", imageDef.Spec.Destination.Repository))
		} else if err != nil {
			return nil, fmt.Errorf("failed to get destination repository %q: %w", imageDef.Spec.Destination.Repository, err)
		} else {
			specType, err := repo.Spec.Discriminator()
			if err != nil {
				return nil, fmt.Errorf("failed to get destination repository spec type: %w", err)
			}
			if specType != string(domain.RepoSpecTypeOci) {
				errs = append(errs, fmt.Errorf("spec.destination.repository: Repository %q must be of type 'oci'", imageDef.Spec.Destination.Repository))
			} else {
				ociSpec, err := repo.Spec.AsOciRepoSpec()
				if err != nil {
					return nil, fmt.Errorf("failed to get destination repository OCI spec: %w", err)
				}
				accessMode := lo.FromPtrOr(ociSpec.AccessMode, domain.Read)
				if accessMode != domain.ReadWrite {
					errs = append(errs, fmt.Errorf("spec.destination.repository: Repository %q must have 'ReadWrite' access mode", imageDef.Spec.Destination.Repository))
				}
			}
		}
	}
	errs = append(errs, ValidateImageName(&imageDef.Spec.Destination.ImageName, "spec.destination.imageName")...)

	return errs, nil
}
