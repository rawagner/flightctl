package tasks

import (
	"context"
	"fmt"

	maincorev1alpha1 "github.com/flightctl/flightctl/api/core/v1alpha1"
	coredomain "github.com/flightctl/flightctl/internal/domain"
	"github.com/flightctl/flightctl/internal/imagebuilder_api/domain"
	imagebuilderapi "github.com/flightctl/flightctl/internal/imagebuilder_api/service"
	"github.com/flightctl/flightctl/internal/service/common"
	"github.com/flightctl/flightctl/internal/worker_client"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
)

// HandleImageBuildUpdate handles ImageBuild ResourceUpdated events
// If the ImageBuild is completed, it requeues related ImageExports that haven't started yet
// This method is public to allow testing with mocked services
func (c *Consumer) HandleImageBuildUpdate(ctx context.Context, eventWithOrgId worker_client.EventWithOrgId, log logrus.FieldLogger) error {
	event := eventWithOrgId.Event
	orgID := eventWithOrgId.OrgId
	imageBuildName := event.InvolvedObject.Name

	log = log.WithField("imageBuild", imageBuildName).WithField("orgId", orgID)
	log.Info("Handling ImageBuild update event")

	// Load the ImageBuild resource
	imageBuild, status := c.imageBuilderService.ImageBuild().Get(ctx, orgID, imageBuildName, false)
	if imageBuild == nil || !imagebuilderapi.IsStatusOK(status) {
		return fmt.Errorf("failed to load ImageBuild %q: %v", imageBuildName, status)
	}

	// Check if ImageBuild is completed
	if imageBuild.Status == nil || imageBuild.Status.Conditions == nil {
		log.Debug("ImageBuild has no status or conditions, skipping requeue of ImageExports")
		return nil
	}

	readyCondition := domain.FindImageBuildStatusCondition(*imageBuild.Status.Conditions, domain.ImageBuildConditionTypeReady)
	if readyCondition == nil ||
		readyCondition.Status != domain.ConditionStatusTrue ||
		readyCondition.Reason != string(domain.ImageBuildConditionReasonCompleted) {
		log.Debug("ImageBuild is not completed, skipping requeue of ImageExports")
		return nil
	}

	log.Info("ImageBuild is completed, checking for related ImageExports to requeue and catalog sync")

	// If the build references an ImageDefinition, sync catalog items
	if imageBuild.Spec.ImageDefinitionRef != nil && *imageBuild.Spec.ImageDefinitionRef != "" {
		if err := c.syncCatalogItems(ctx, orgID, imageBuild, log); err != nil {
			log.WithError(err).Warn("Failed to sync catalog items after build completion")
			// Non-fatal: continue with ImageExport requeue
		}
	}

	// Find ImageExports that reference this ImageBuild
	// Use field selector to filter at database level by imageBuildRef
	fieldSelectorStr := fmt.Sprintf("spec.source.imageBuildRef = %s", imageBuildName)
	imageExports, status := c.imageBuilderService.ImageExport().List(ctx, orgID, domain.ListImageExportsParams{
		FieldSelector: &fieldSelectorStr,
	})
	if !imagebuilderapi.IsStatusOK(status) {
		return fmt.Errorf("failed to list ImageExports for ImageBuild %q: %v", imageBuildName, status)
	}
	if imageExports == nil || len(imageExports.Items) == 0 {
		log.Debug("No ImageExports found for this ImageBuild")
		return nil
	}

	// Filter for ImageExports that need requeueing:
	// - Have Pending reason, OR
	// - Don't have a Ready condition at all (not started yet)
	requeuedCount := 0
	for _, imageExport := range imageExports.Items {
		// Check if this ImageExport needs requeueing
		shouldRequeue := false
		if imageExport.Status == nil || imageExport.Status.Conditions == nil {
			// No status or conditions - needs requeueing
			shouldRequeue = true
		} else {
			// Look for Ready condition
			readyCondition := domain.FindImageExportStatusCondition(*imageExport.Status.Conditions, domain.ImageExportConditionTypeReady)
			if readyCondition == nil {
				// No Ready condition - needs requeueing
				shouldRequeue = true
			} else if readyCondition.Reason == string(domain.ImageExportConditionReasonPending) {
				// Has Pending reason - needs requeueing
				shouldRequeue = true
			}
			// Skip if already Completed, Failed, or Converting
		}

		if !shouldRequeue {
			continue
		}
		exportName := lo.FromPtr(imageExport.Metadata.Name)
		if exportName == "" {
			log.Warn("ImageExport has empty name, skipping")
			continue
		}

		requeueEvent := common.GetResourceCreatedOrUpdatedSuccessEvent(
			ctx,
			true,
			coredomain.ResourceKind(string(domain.ResourceKindImageExport)),
			exportName,
			nil,
			log,
			nil,
		)
		if requeueEvent == nil {
			log.WithField("imageExport", exportName).Warn("Failed to create requeue event")
			continue
		}

		// Enqueue the event
		if err := c.enqueueEvent(ctx, orgID, requeueEvent, log); err != nil {
			log.WithError(err).WithField("imageExport", exportName).Error("Failed to requeue ImageExport")
			continue
		}

		log.WithField("imageExport", exportName).Info("Requeued ImageExport due to ImageBuild completion")
		requeuedCount++
	}

	if requeuedCount > 0 {
		log.WithField("requeuedCount", requeuedCount).Info("Requeued ImageExports due to ImageBuild completion")
	} else {
		log.Debug("No ImageExports needed requeueing")
	}

	return nil
}

// syncCatalogItems finds all ImageCatalogExport resources referencing the same ImageDefinition
// and upserts a new version entry into the corresponding CatalogItem for each one.
func (c *Consumer) syncCatalogItems(ctx context.Context, orgID uuid.UUID, imageBuild *domain.ImageBuild, log logrus.FieldLogger) error {
	if imageBuild.Status == nil || imageBuild.Status.ResolvedVersion == nil {
		log.Debug("ImageBuild has no resolvedVersion in status, skipping catalog sync")
		return nil
	}

	defName := lo.FromPtr(imageBuild.Spec.ImageDefinitionRef)
	resolvedVersion := lo.FromPtr(imageBuild.Status.ResolvedVersion)
	resolvedDestination := imageBuild.Status.ResolvedDestination

	exports, err := c.imageBuilderService.ImageCatalogExport().ListByImageDefinition(ctx, orgID, defName)
	if err != nil {
		return fmt.Errorf("failed to list ImageCatalogExport resources for ImageDefinition %q: %w", defName, err)
	}
	if len(exports) == 0 {
		log.WithField("imageDefinition", defName).Debug("No ImageCatalogExport resources found, skipping catalog sync")
		return nil
	}

	for _, export := range exports {
		catalogRef := export.Spec.CatalogRef
		catalogItemName := export.Spec.CatalogItemName
		effectiveName := defName
		if catalogItemName != nil && *catalogItemName != "" {
			effectiveName = *catalogItemName
		}

		if err := c.upsertCatalogItem(ctx, orgID, export, effectiveName, catalogRef, resolvedVersion, resolvedDestination, log); err != nil {
			log.WithError(err).
				WithField("catalog", catalogRef).
				WithField("catalogItem", effectiveName).
				Warn("Failed to upsert CatalogItem")
			// Continue with remaining exports
		}
	}

	return nil
}

// upsertCatalogItem creates or updates a CatalogItem in the given catalog with a new version entry.
func (c *Consumer) upsertCatalogItem(
	ctx context.Context,
	orgID uuid.UUID,
	export domain.ImageCatalogExport,
	itemName, catalogRef, resolvedVersion string,
	resolvedDest *domain.ImageBuildDestination,
	log logrus.FieldLogger,
) error {
	newVersion := maincorev1alpha1.CatalogItemVersion{
		Version:  resolvedVersion,
		Channels: []string{"latest"},
		References: map[string]string{
			"container": resolvedVersion,
		},
	}

	var versions []maincorev1alpha1.CatalogItemVersion
	var artifacts []maincorev1alpha1.CatalogItemArtifact

	existingItem, getErr := c.mainStore.Catalog().GetItem(ctx, orgID, catalogRef, itemName)
	if getErr == nil && existingItem != nil {
		versions = existingItem.Spec.Versions
		artifacts = existingItem.Spec.Artifacts

		// Set replaces to the latest existing version
		if len(versions) > 0 {
			lastVer := versions[len(versions)-1].Version
			newVersion.Replaces = &lastVer
		}

		// Skip if this version already exists
		for _, v := range versions {
			if v.Version == resolvedVersion {
				log.WithField("catalog", catalogRef).
					WithField("catalogItem", itemName).
					WithField("version", resolvedVersion).
					Debug("Version already exists in CatalogItem, skipping")
				return nil
			}
		}
		versions = append(versions, newVersion)
	} else {
		// New item — build artifacts from the resolved destination
		versions = []maincorev1alpha1.CatalogItemVersion{newVersion}
		imageName := ""
		if resolvedDest != nil {
			imageName = resolvedDest.ImageName
		}
		artifacts = []maincorev1alpha1.CatalogItemArtifact{
			{
				Type: maincorev1alpha1.CatalogItemArtifactTypeContainer,
				Uri:  imageName,
			},
		}
	}

	itemType := maincorev1alpha1.CatalogItemTypeOS
	item := &maincorev1alpha1.CatalogItem{
		ApiVersion: "flightctl.io/v1alpha1",
		Kind:       "CatalogItem",
		Metadata: maincorev1alpha1.CatalogItemMeta{
			Catalog: catalogRef,
		},
		Spec: maincorev1alpha1.CatalogItemSpec{
			Type:      itemType,
			Artifacts: artifacts,
			Versions:  versions,
		},
	}
	item.Metadata.Name = &itemName

	// Populate display metadata from the export spec
	if export.Spec.DisplayName != nil {
		item.Spec.DisplayName = export.Spec.DisplayName
	}
	if export.Spec.ShortDescription != nil {
		item.Spec.ShortDescription = export.Spec.ShortDescription
	}
	if export.Spec.Provider != nil {
		item.Spec.Provider = export.Spec.Provider
	}
	if export.Spec.Support != nil {
		item.Spec.Support = export.Spec.Support
	}
	if export.Spec.Homepage != nil {
		item.Spec.Homepage = export.Spec.Homepage
	}
	if export.Spec.DocumentationUrl != nil {
		item.Spec.DocumentationUrl = export.Spec.DocumentationUrl
	}

	_, _, err := c.mainStore.Catalog().CreateOrUpdateItem(ctx, orgID, catalogRef, item)
	if err != nil {
		return fmt.Errorf("failed to upsert CatalogItem %q in catalog %q: %w", itemName, catalogRef, err)
	}

	log.WithField("catalog", catalogRef).
		WithField("catalogItem", itemName).
		WithField("version", resolvedVersion).
		Info("Successfully upserted CatalogItem version")

	return nil
}
