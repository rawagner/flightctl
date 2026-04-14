package imagebuilder

const (
	APIGroup = "flightctl.io"

	StatusKind = "Status"

	ImageBuildAPIVersion = "v1alpha1"
	ImageBuildListKind   = "ImageBuildList"

	ImageExportAPIVersion = "v1alpha1"
	ImageExportListKind   = "ImageExportList"

	ImageDefinitionAPIVersion = "v1alpha1"
	ImageDefinitionListKind   = "ImageDefinitionList"

	ImageCatalogExportAPIVersion = "v1alpha1"
	ImageCatalogExportListKind   = "ImageCatalogExportList"

	// LogStreamCompleteMarker is sent by the server when a log stream is complete.
	// The CLI uses this to distinguish between orderly completion and abrupt disconnection.
	LogStreamCompleteMarker = "<<STREAM_COMPLETE>>"
)
