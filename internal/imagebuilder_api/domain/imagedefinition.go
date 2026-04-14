package domain

import (
	api "github.com/flightctl/flightctl/api/imagebuilder/v1alpha1"
)

// ========== Resource Types ==========

type ImageDefinition = api.ImageDefinition
type ImageDefinitionList = api.ImageDefinitionList

// ========== Spec Types ==========

type ImageDefinitionSpec = api.ImageDefinitionSpec
type ImageDefinitionDestination = api.ImageDefinitionDestination

// ========== API Parameters ==========

type ListImageDefinitionsParams = api.ListImageDefinitionsParams

// ========== Resource Kind ==========

const (
	ResourceKindImageDefinition = api.ResourceKindImageDefinition
)

// ========== List Kind ==========

const (
	ImageDefinitionListKind = api.ImageDefinitionListKind
)

// ========== API Version ==========

const (
	ImageDefinitionAPIVersion = api.ImageDefinitionAPIVersion
)
