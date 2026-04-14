package domain

import (
	api "github.com/flightctl/flightctl/api/imagebuilder/v1alpha1"
)

// ========== Resource Types ==========

type ImageCatalogExport = api.ImageCatalogExport
type ImageCatalogExportList = api.ImageCatalogExportList

// ========== Spec Types ==========

type ImageCatalogExportSpec = api.ImageCatalogExportSpec

// ========== API Parameters ==========

type ListImageCatalogExportsParams = api.ListImageCatalogExportsParams

// ========== Resource Kind ==========

const (
	ResourceKindImageCatalogExport = api.ResourceKindImageCatalogExport
)

// ========== List Kind ==========

const (
	ImageCatalogExportListKind = api.ImageCatalogExportListKind
)

// ========== API Version ==========

const (
	ImageCatalogExportAPIVersion = api.ImageCatalogExportAPIVersion
)
